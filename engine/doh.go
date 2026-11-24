package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// CryptoStorm publishes per-city endpoints at https://cryptostorm.is/blog/doh.
const berlinDoHHost = "berlin.cstorm.is"
const berlinDoHIP = "37.120.217.76"

var errNoAddress = errors.New("DNS не вернул публичный адрес назначения")

func (c Config) newDNSClient() *http.Client {
	tr := &http.Transport{
		ForceAttemptHTTP2: true, IdleConnTimeout: time.Minute,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			if address != berlinDoHHost+":443" {
				return nil, errors.New("неожиданный адрес DNS-сервера")
			}
			return c.upstream(ctx, berlinDoHIP, 443)
		},
	}
	return &http.Client{Transport: tr, Timeout: 8 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}

func dnsAddresses(response []byte, q dnsmessage.Question) ([]netip.Addr, error) {
	var m dnsmessage.Message
	if e := m.Unpack(response); e != nil || !m.Response || m.Truncated || m.ID != 0 || m.OpCode != 0 ||
		len(m.Questions) != 1 || m.Questions[0].Type != q.Type || m.Questions[0].Class != q.Class ||
		!strings.EqualFold(m.Questions[0].Name.String(), q.Name.String()) {
		return nil, errors.New("неверный ответ DNS")
	}
	if m.RCode == dnsmessage.RCodeNameError {
		return nil, errNoAddress
	}
	if m.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("ошибка DNS: %v", m.RCode)
	}
	name := strings.ToLower(q.Name.String())
	aliases := map[string]string{}
	for _, r := range m.Answers {
		if v, ok := r.Body.(*dnsmessage.CNAMEResource); ok && r.Header.Class == q.Class {
			aliases[strings.ToLower(r.Header.Name.String())] = strings.ToLower(v.CNAME.String())
		}
	}
	for steps := 0; aliases[name] != ""; steps++ {
		if steps >= 16 {
			return nil, errors.New("слишком длинная цепочка CNAME")
		}
		name = aliases[name]
	}
	var ips []netip.Addr
	for _, r := range m.Answers {
		if r.Header.Class != q.Class || r.Header.Type != q.Type || !strings.EqualFold(r.Header.Name.String(), name) {
			continue
		}
		var ip netip.Addr
		switch v := r.Body.(type) {
		case *dnsmessage.AResource:
			ip = netip.AddrFrom4(v.A)
		case *dnsmessage.AAAAResource:
			ip = netip.AddrFrom16(v.AAAA).Unmap()
		}
		if ip.IsGlobalUnicast() && !ip.IsPrivate() {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}
func (c Config) resolve(ctx context.Context, name string, typ dnsmessage.Type) ([]netip.Addr, error) {
	qname, e := dnsmessage.NewName(name + ".")
	if e != nil {
		return nil, e
	}
	q := dnsmessage.Question{Name: qname, Type: typ, Class: dnsmessage.ClassINET}
	msg := dnsmessage.Message{Header: dnsmessage.Header{RecursionDesired: true}, Questions: []dnsmessage.Question{q}}
	wire, e := msg.Pack()
	if e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+berlinDoHHost+"/dns-query", bytes.NewReader(wire))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, e := c.resolver.Do(req)
	if e != nil {
		return nil, fmt.Errorf("берлинский DNS недоступен: %w", e)
	}
	defer resp.Body.Close()
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != 200 || mt != "application/dns-message" {
		return nil, fmt.Errorf("берлинский DNS вернул HTTP %d (%s)", resp.StatusCode, mt)
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if e != nil || len(b) > 65535 {
		return nil, errors.New("повреждённый ответ DNS")
	}
	return dnsAddresses(b, q)
}
func (c Config) dial(ctx context.Context, host string, port int) (net.Conn, error) {
	if e := c.validate(); e != nil {
		return nil, e
	}
	if c.DNSMode != "berlin" || net.ParseIP(host) != nil {
		return c.upstream(ctx, host, port)
	}
	host = canonical(host)
	if !validName(host) || port < 1 || port > 65535 {
		return nil, errors.New("неверный адрес назначения")
	}
	if c.resolver == nil {
		c.resolver = c.newDNSClient()
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	var last error
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		ips, e := c.resolve(ctx, host, typ)
		if e != nil {
			return nil, e
		}
		for _, ip := range ips {
			conn, e := c.upstream(ctx, ip.String(), port)
			if e == nil {
				return conn, nil
			}
			last = e
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
	}
	if last != nil {
		return nil, last
	}
	return nil, errNoAddress
}
