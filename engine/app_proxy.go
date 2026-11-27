package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"
)

func parseDestination(line string) (string, string, int) {
	if !strings.Contains(line, " ") {
		return "", line, 443
	}
	f := strings.Fields(line)
	if len(f) != 3 {
		return "", "", 0
	}
	n, _ := strconv.Atoi(f[2])
	return f[0], canonical(f[1]), n
}
func workerDial(path, scope, host string, port int) (net.Conn, error) {
	if strings.ContainsAny(scope+host, " \t\r\n") {
		return nil, errors.New(message("invalid address"))
	}
	n, e := net.DialTimeout("unix", path, time.Second)
	if e != nil {
		return nil, e
	}
	n.SetDeadline(time.Now().Add(12 * time.Second))
	_, e = fmt.Fprintf(n, "%s %s %d\n", scope, host, port)
	if e == nil {
		var result string
		result, e = limitedLines(n)
		if e == nil && result != "OK" {
			e = errors.New(message("forwarding is blocked"))
		}
	}
	if e != nil {
		n.Close()
		return nil, e
	}
	n.SetDeadline(time.Time{})
	return n, nil
}

type applicationProxy struct {
	scope  string
	path   string
	policy Policy
}

func (p applicationProxy) dial(_ context.Context, _ string, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	host = canonical(host)
	n, err := strconv.Atoi(port)
	if err != nil || p.policy.routeFor(p.scope, host, n) == blockedRoute {
		return nil, errors.New(message("address blocked by a rule"))
	}
	return workerDial(p.path, p.scope, host, n)
}
func (p applicationProxy) handler() http.Handler {
	transport := &http.Transport{DialContext: p.dial, DisableKeepAlives: true, ResponseHeaderTimeout: 40 * time.Second}
	rp := &httputil.ReverseProxy{Transport: transport, Rewrite: func(r *httputil.ProxyRequest) {
		r.Out.Host = r.Out.URL.Host
		r.Out.Header.Del("Forwarded")
		r.Out.Header.Del("Via")
	}, ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) { http.Error(w, "Proxy unavailable", 502) }}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "CONNECT" {
			n, e := p.dial(r.Context(), "tcp", r.Host)
			if e != nil {
				http.Error(w, "Connection denied or unavailable", 502)
				return
			}
			defer n.Close()
			local, b, e := w.(http.Hijacker).Hijack()
			if e != nil {
				return
			}
			defer local.Close()
			if _, e = io.WriteString(local, "HTTP/1.1 200 Connection established\r\n\r\n"); e != nil {
				return
			}
			pipe(buffered{local, b.Reader}, n)
			return
		}
		if r.Method == "GET" && strings.EqualFold(r.Host, checkHost+":17688") && r.URL.Path == "/check" {
			c, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				diagnostic(c, []byte("GET /check HTTP/1.1\r\nHost: "+checkHost+":17688\r\n\r\n"), "App profile → local proxy")
			}
			return
		}
		if r.URL.Scheme != "http" || r.URL.Host == "" || r.URL.User != nil {
			http.Error(w, "HTTP proxy request required", 400)
			return
		}
		port := 80
		if r.URL.Port() != "" {
			port, _ = strconv.Atoi(r.URL.Port())
		}
		if p.policy.routeFor(p.scope, canonical(r.URL.Hostname()), port) == blockedRoute {
			http.Error(w, "Destination denied", 403)
			return
		}
		rp.ServeHTTP(w, r)
	})
}
func serveApp(l net.Listener, uid int, scope string) error {
	server := http.Server{Handler: applicationProxy{scope, socket(uid), activePolicy}.handler(), ReadHeaderTimeout: 6 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32768}
	return server.Serve(l)
}
