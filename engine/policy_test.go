package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCustomScopeIsolation(t *testing.T) {
	a, b := catalog.Apps[0].ID, catalog.Apps[1].ID
	p := Policy{[]string{"*.PUBLIC.example.", "public.example"}, []AppRule{{a, false, []string{"allowed.example"}}, {b, true, nil}}}
	if e := p.validate(); e != nil || !slices.Equal(p.Domains, []string{"public.example"}) {
		t.Fatalf("%v: %v", p, e)
	}
	for _, tc := range []struct {
		scope, host string
		port        int
		ok          bool
	}{
		{"", "child.public.example", 443, true}, {"", "child.public.example", 80, false}, {"", "almostpublic.example", 443, false},
		{a, "child.allowed.example", 80, true}, {a, "public.example", 443, false}, {b, "other.example", 443, true},
		{b, "127.0.0.1", 443, false}, {b, "::1", 443, false}, {b, "1.1.1.1", 443, true}, {"missing", "other.example", 443, false},
	} {
		if p.allows(tc.scope, tc.host, tc.port) != tc.ok {
			t.Errorf("scope: %+v", tc)
		}
	}
	for _, bad := range []string{"https://foo.example", "localhost", "10.0.0.1", "a..example", "test.local", "foo.example:443", "a/b.example", "."} {
		if _, err := normalized([]string{bad}); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestHostMigrationAndRetry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	original := "127.0.0.1 localhost\n"
	old := blockFor([]string{"service.example", "unused.example"}, "extra.service.example", "api.unused.example")
	next := []string{"service.example", "new.example"}
	aliases := keptAliases(old, next)
	if !slices.Equal(aliases, []string{"extra.service.example"}) {
		t.Fatal(aliases)
	}
	block := blockFor(next, aliases...)
	if err := os.WriteFile(path, []byte(original+old), 0644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := replaceHosts(path, old, block, next); err != nil {
			t.Fatal(err)
		}
	}
	if err := replaceHosts(path, block, "", nil); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != original {
		t.Fatal(string(data))
	}
}

func TestApplicationProxyForwardAndOutage(t *testing.T) {
	dir, e := os.MkdirTemp("/tmp", "pg-scope-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "worker")
	scope := catalog.Apps[0].ID
	p := Policy{Applications: []AppRule{{scope, false, []string{"allowed.example"}}}}
	server := httptest.NewServer(applicationProxy{scope, path, p}.handler())
	defer server.Close()
	proxy, _ := url.Parse(server.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 3 * time.Second}
	for _, method := range []string{"HTTP", "CONNECT"} {
		l, e := net.Listen("unix", path)
		if e != nil {
			t.Fatal(e)
		}
		done := make(chan error, 1)
		go func() {
			conn, e := l.Accept()
			if e != nil {
				done <- e
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			request, e := limitedLines(conn)
			if e != nil {
				done <- e
				return
			}
			port := 80
			if method == "CONNECT" {
				port = 8443
			}
			if request != fmt.Sprintf("%s allowed.example %d", scope, port) {
				done <- fmt.Errorf("unexpected worker request %q", request)
				return
			}
			io.WriteString(conn, "OK\n")
			if method == "CONNECT" {
				_, e = io.WriteString(conn, "proxied")
				done <- e
				return
			}
			r, e := http.ReadRequest(bufio.NewReader(conn))
			if e == nil && (r.Host != "allowed.example" || r.URL.Path != "/path" || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Proxy-Authorization") != "") {
				e = fmt.Errorf("invalid origin request")
			}
			io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nproxied")
			done <- e
		}()
		if method == "HTTP" {
			req, _ := http.NewRequest("GET", "http://allowed.example/path", nil)
			req.Header.Set("X-Forwarded-For", "test")
			req.Header.Set("Proxy-Authorization", "test")
			resp, e := client.Do(req)
			if e != nil {
				t.Fatal(e)
			}
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(data) != "proxied" {
				t.Fatal(string(data))
			}
		} else {
			c, e := net.DialTimeout("tcp", proxy.Host, time.Second)
			if e != nil {
				t.Fatal(e)
			}
			c.SetDeadline(time.Now().Add(4 * time.Second))
			io.WriteString(c, "CONNECT allowed.example:8443 HTTP/1.1\r\nHost: allowed.example:8443\r\n\r\n")
			data, e := io.ReadAll(c)
			c.Close()
			if e != nil || !strings.HasSuffix(string(data), "proxied") {
				t.Fatal(string(data), e)
			}
		}
		if e := <-done; e != nil {
			t.Fatal(e)
		}
		l.Close()
	}
	for dest, code := range map[string]int{"http://allowed.example": 502, "http://another.example": 403} {
		resp, e := client.Get(dest)
		if e != nil {
			t.Fatal(e)
		}
		resp.Body.Close()
		if resp.StatusCode != code {
			t.Errorf("%s: %d", dest, resp.StatusCode)
		}
	}
}
