package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Kind     string `json:"kind"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	// Optional numeric address avoids even a local DNS lookup for the proxy itself.
	Address  string `json:"address"`
	DNSMode  string `json:"dnsMode"`
	resolver *http.Client
}
type Report struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	Zone    string `json:"zone"`
}

func validName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func canonical(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".") }
func protected(s string) bool   { return matches(activePolicy.Domains, s) }
func (c Config) validate() error {
	if c.DNSMode != "" && c.DNSMode != "upstream" && c.DNSMode != "berlin" {
		return errors.New(message("unknown DNS mode"))
	}
	if c.DNSMode == "berlin" && net.ParseIP(c.Address) == nil && net.ParseIP(c.Host) == nil {
		return errors.New(message("Enter the proxy’s numeric IP address to use Berlin DNS."))
	}
	if c.Kind != "http" && c.Kind != "https" && c.Kind != "socks5" {
		return errors.New(message("unknown proxy type"))
	}
	if !validName(canonical(c.Host)) && net.ParseIP(c.Host) == nil {
		return errors.New(message("invalid server name"))
	}
	if c.Address != "" && net.ParseIP(c.Address) == nil {
		return errors.New(message("the server IP must be numeric"))
	}
	if c.Port < 1 || c.Port > 65535 || strings.ContainsAny(c.User, "\r\n:") || len(c.User) > 255 || len(c.Password) > 255 || (c.User == "") != (c.Password == "") {
		return errors.New(message("check the port, username, and password"))
	}
	return nil
}

type buffered struct {
	net.Conn
	r *bufio.Reader
}

func (b buffered) Read(p []byte) (int, error) { return b.r.Read(p) }
func (c Config) upstream(ctx context.Context, host string, port int) (net.Conn, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if (!validName(host) && net.ParseIP(host) == nil) || port < 1 || port > 65535 {
		return nil, errors.New(message("invalid destination address"))
	}
	address := c.Address
	if address == "" {
		address = c.Host
	}
	raw, err := (&net.Dialer{Timeout: 6 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(c.Port)))
	if err != nil {
		return nil, errors.New(message("could not connect to the proxy"))
	}
	success := false
	defer func() {
		if !success {
			raw.Close()
		}
	}()
	conn := raw
	handshakeDeadline := time.Now().Add(9 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(handshakeDeadline) {
		handshakeDeadline = end
	}
	conn.SetDeadline(handshakeDeadline)
	if c.Kind == "https" {
		t := tls.Client(raw, &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12})
		if err = t.HandshakeContext(ctx); err != nil {
			return nil, errors.New(message("TLS connection to the proxy failed"))
		}
		conn = t
	}
	if c.Kind == "socks5" {
		err = c.socks(conn, host, port)
	} else {
		dst := net.JoinHostPort(host, strconv.Itoa(port))
		headers := ""
		if c.User != "" {
			headers = "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(c.User+":"+c.Password)) + "\r\n"
		}
		_, err = io.WriteString(conn, "CONNECT "+dst+" HTTP/1.1\r\nHost: "+dst+"\r\n"+headers+"\r\n")
		if err == nil {
			limited := &io.LimitedReader{R: conn, N: 32768}
			br := bufio.NewReader(limited)
			var resp *http.Response
			resp, err = http.ReadResponse(br, &http.Request{Method: "CONNECT"})
			if err == nil && resp.StatusCode != 200 {
				err = fmt.Errorf(message("proxy returned HTTP %d"), resp.StatusCode)
			}
			limited.N = 1 << 62
			conn = buffered{conn, br}
		}
	}
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	success = true
	return conn, nil
}
func (c Config) socks(n net.Conn, host string, port int) error {
	method := byte(0)
	if c.User != "" {
		method = 2
	}
	if _, err := n.Write([]byte{5, 1, method}); err != nil {
		return err
	}
	var pair [2]byte
	if _, err := io.ReadFull(n, pair[:]); err != nil {
		return err
	}
	if pair != [2]byte{5, method} {
		return errors.New(message("SOCKS5 rejected the authentication method"))
	}
	if method == 2 {
		msg := append([]byte{1, byte(len(c.User))}, c.User...)
		msg = append(msg, byte(len(c.Password)))
		msg = append(msg, c.Password...)
		if _, err := n.Write(msg); err != nil {
			return err
		}
		if _, err := io.ReadFull(n, pair[:]); err != nil {
			return err
		}
		if pair != [2]byte{1, 0} {
			return errors.New(message("SOCKS5 rejected the username or password"))
		}
	}
	msg := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			msg = append(msg, 1)
			msg = append(msg, v4...)
		} else {
			msg = append(msg, 4)
			msg = append(msg, ip.To16()...)
		}
	} else {
		msg = append(msg, 3, byte(len(host)))
		msg = append(msg, host...)
	}
	msg = append(msg, byte(port>>8), byte(port))
	if _, err := n.Write(msg); err != nil {
		return err
	}
	var h [4]byte
	if _, err := io.ReadFull(n, h[:]); err != nil {
		return err
	}
	if h[0] != 5 || h[1] != 0 || h[2] != 0 {
		return errors.New(message("SOCKS5 rejected the connection"))
	}
	var size int
	switch h[3] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(n, l[:]); err != nil {
			return err
		}
		size = int(l[0])
	default:
		return errors.New(message("invalid SOCKS5 response"))
	}
	_, err := io.CopyN(io.Discard, n, int64(size+2))
	return err
}
func (c Config) get(ctx context.Context, host, path string) ([]byte, error) {
	n, err := c.dial(ctx, host, 443)
	if err != nil {
		return nil, err
	}
	defer n.Close()
	deadline := time.Now().Add(10 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	n.SetDeadline(deadline)
	t := tls.Client(n, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err = t.HandshakeContext(ctx); err != nil {
		return nil, errors.New(message("TLS verification of the diagnostic service failed"))
	}
	req, _ := http.NewRequest("GET", "https://"+host+path, nil)
	req.Close = true
	req.Header.Set("Cache-Control", "no-cache")
	if err = req.Write(t); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(t), req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, &diagnosticHTTPError{host, resp.StatusCode, resp.Header.Get("Retry-After")}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32768))
	return body, err
}
func safeZone(s string) bool {
	if s == "" || s == "Local" || strings.Contains(s, "..") || strings.HasPrefix(s, "/") {
		return false
	}
	_, err := time.LoadLocation(s)
	return err == nil
}
