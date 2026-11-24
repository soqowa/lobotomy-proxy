package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	activePolicy = Policy{Domains: []string{"service.example", "assets.example"}}
	os.Exit(m.Run())
}
func editHostsAt(file string, add bool) error {
	if add {
		return replaceHosts(file, "", hostBlock(), activePolicy.Domains)
	}
	return replaceHosts(file, hostBlock(), "", nil)
}

func proxyFixture(t *testing.T, mode string, server func(net.Conn)) Config {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		n, e := l.Accept()
		if e != nil {
			return
		}
		defer n.Close()
		n.SetDeadline(time.Now().Add(2 * time.Second))
		server(n)
	}()
	return Config{Kind: mode, Host: "upstream.invalid", Address: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port, User: "sample", Password: "local-test"}
}
func TestHTTPRemoteNameAndNoFallback(t *testing.T) {
	for _, code := range []int{200, 407, 502} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			got := make(chan string, 1)
			c := proxyFixture(t, "http", func(n net.Conn) {
				req, e := http.ReadRequest(bufio.NewReader(n))
				if e != nil {
					got <- e.Error()
					return
				}
				if req.Header.Get("Proxy-Authorization") == "" {
					got <- "missing auth"
					return
				}
				got <- req.Host
				fmt.Fprintf(n, "HTTP/1.1 %d Result\r\n\r\nhello", code)
			})
			n, e := c.dial(context.Background(), "nonexistent.invalid", 443)
			if s := <-got; s != "nonexistent.invalid:443" {
				t.Fatal(s)
			}
			if code != 200 {
				if e == nil || n != nil {
					t.Fatal("accepted denial")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer n.Close()
			b, _ := io.ReadAll(n)
			if string(b) != "hello" {
				t.Fatalf("lost prefetched bytes: %q", b)
			}
		})
	}
}
func TestSocksRemoteNameAndAuth(t *testing.T) {
	for _, deny := range []bool{false, true} {
		c := proxyFixture(t, "socks5", func(n net.Conn) {
			r := bufio.NewReader(n)
			h := make([]byte, 3)
			io.ReadFull(r, h)
			if !bytes.Equal(h, []byte{5, 1, 2}) {
				return
			}
			n.Write([]byte{5, 2})
			v, _ := r.ReadByte()
			u, _ := r.ReadByte()
			usr := make([]byte, u)
			io.ReadFull(r, usr)
			p, _ := r.ReadByte()
			pwd := make([]byte, p)
			io.ReadFull(r, pwd)
			if v != 1 || string(usr) != "sample" || string(pwd) != "local-test" {
				return
			}
			if deny {
				n.Write([]byte{1, 1})
				return
			}
			n.Write([]byte{1, 0})
			header := make([]byte, 5)
			io.ReadFull(r, header)
			name := make([]byte, header[4])
			io.ReadFull(r, name)
			port := make([]byte, 2)
			io.ReadFull(r, port)
			if !bytes.Equal(header[:4], []byte{5, 1, 0, 3}) || string(name) != "unresolvable.invalid" || binary.BigEndian.Uint16(port) != 443 {
				return
			}
			n.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
			n.Write([]byte("proxied"))
		})
		n, e := c.dial(context.Background(), "unresolvable.invalid", 443)
		if deny {
			if e == nil || n != nil {
				t.Fatal("SOCKS auth failure accepted")
			}
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		b, _ := io.ReadAll(n)
		n.Close()
		if string(b) != "proxied" {
			t.Fatal(string(b))
		}
	}
}
func query(name string, typ uint16) []byte {
	b := []byte{1, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0, byte(typ>>8), byte(typ), 0, 1)
}
func TestScopedDNS(t *testing.T) {
	for _, name := range []string{"api.service.example", "deep.frame.assets.example", "SERVICE.EXAMPLE"} {
		for _, typ := range []uint16{1, 28, 65, 64, 15} {
			r := answer(query(name, typ))
			if r == nil || r[3] != 0 {
				t.Fatal(name, typ)
			}
			if typ == 1 {
				if r[7] != 1 || !bytes.Equal(r[len(r)-4:], net.ParseIP(localIP).To4()) {
					t.Fatal("non-loopback DNS answer")
				}
			} else if r[7] != 0 {
				t.Fatal("expected NODATA", typ)
			}
		}
	}
	for _, s := range []string{"notservice.example", "service.example.example.com", "example.org"} {
		if answer(query(s, 1))[3] != 5 {
			t.Fatal("should refuse", s)
		}
	}
	if answer([]byte{1, 2, 3}) != nil {
		t.Fatal("bad DNS packet")
	}
}
func TestSNI(t *testing.T) {
	for _, name := range []string{"api.service.example", "service.example.evil.invalid"} {
		a, b := net.Pipe()
		a.SetDeadline(time.Now().Add(time.Second))
		b.SetDeadline(time.Now().Add(time.Second))
		go func() { _ = tls.Client(a, &tls.Config{ServerName: name}).Handshake(); a.Close() }()
		h, hello := inspect(b)
		b.Close()
		if protected(name) {
			if h != name || len(hello) < 32 || hello[0] != 22 {
				t.Fatal(h, len(hello))
			}
		} else if h != "" {
			t.Fatal("foreign SNI")
		}
	}
}
func TestPacRefusesIPOrForeignAuthority(t *testing.T) {
	for _, h := range []string{"127.0.0.1:443", "[::1]:443", "service.example.example.net:443", "service.example:80"} {
		a, b := net.Pipe()
		go func() { browser(b, socket(501)); b.Close() }()
		fmt.Fprintf(a, "CONNECT %s HTTP/1.1\r\n\r\n", h)
		r, _ := io.ReadAll(a)
		a.Close()
		if !strings.Contains(string(r), "403") {
			t.Fatal(h)
		}
	}
}
func TestLostSystemEvidence(t *testing.T) {
	var out string
	for _, d := range rules() {
		out += "resolver #1\n domain : " + d + "\n nameserver[0] : 127.0.0.1\n port : " + dnsPort + "\n"
	}
	if !dnsOK(out) {
		t.Fatal("valid configuration")
	}
	if dnsOK("") || dnsOK(out+"resolver #77\n domain : api.service.example\n nameserver[0] : 1.1.1.1\n") || dnsOK(strings.ReplaceAll(out, "127.0.0.1", "::1")) {
		t.Fatal("unsafe DNS passed")
	}
	a, b := net.Pipe()
	defer b.Close()
	g := gate{flows: make(map[net.Conn]bool)}
	if g.admit(a) {
		t.Fatal("default should deny")
	}
	g.deadline = time.Now().Add(time.Minute)
	if !g.admit(a) {
		t.Fatal("after verification")
	}
	g.closeAll()
	if g.admit(a) {
		t.Fatal("continued admission")
	}
	b.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := b.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("in-flight connection was not closed", err)
	}
}

func TestRollbackPreservesIndependentChanges(t *testing.T) {
	dir := t.TempDir()
	hosts := dir + "/hosts"
	base := "127.0.0.1 localhost\n127.0.0.1 keep.local\n"
	if e := os.WriteFile(hosts, []byte(base), 0644); e != nil {
		t.Fatal(e)
	}
	if e := editHostsAt(hosts, true); e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(hosts, os.O_APPEND|os.O_WRONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	io.WriteString(f, "::1 later.local\n")
	f.Close()
	if e := editHostsAt(hosts, false); e != nil {
		t.Fatal(e)
	}
	if e := editHostsAt(hosts, false); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(hosts)
	if string(b) != base+"::1 later.local\n" {
		t.Fatal("lost unrelated changes")
	}
	rule := dir + "/rule"
	os.WriteFile(rule, []byte("another tool"), 0644)
	if removeOwned(rule, []byte(splitRule("service.example"))) == nil {
		t.Fatal("removed foreign resolver")
	}
	if b, _ := os.ReadFile(rule); string(b) != "another tool" {
		t.Fatal("foreign resolver changed")
	}
	os.WriteFile(hosts, []byte(base+"192.0.2.1 api.service.example\n"), 0644)
	if editHostsAt(hosts, true) == nil {
		t.Fatal("conflicting DNS entry accepted")
	}
}

// Exercise the same kernel-owned listening socket through a real user launchd job.
// No elevated privileges, DNS changes or system networking writes are required.
func TestLaunchdSocketChild(t *testing.T) {
	if os.Getenv("PROXYGUARD_TEST_CHILD") != "yes" {
		t.Skip("launchd child")
	}
	l, e := streamSocket("TestStream")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	c, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	io.WriteString(c, "activated\n")
	c.Close()
}
func TestLaunchdKeepsSocket(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("requires a per-user bootstrap session")
	}
	tmp := t.TempDir()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	portListener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := fmt.Sprint(portListener.Addr().(*net.TCPAddr).Port)
	portListener.Close()
	label := fmt.Sprintf("local.proxyguard.test.%d", os.Getpid())
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	// Copy the test executable into a stable directory so launchd never races Go's build cleanup.
	binary := tmp + "/child"
	b, e := os.ReadFile(exe)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(binary, b, 0755); e != nil {
		t.Fatal(e)
	}
	xml := `<plist version="1.0"><dict><key>Label</key><string>` + label + `</string><key>ProgramArguments</key><array><string>` + binary + `</string><string>-test.run=^TestLaunchdSocketChild$</string></array><key>EnvironmentVariables</key><dict><key>PROXYGUARD_TEST_CHILD</key><string>yes</string></dict><key>ThrottleInterval</key><integer>1</integer><key>Sockets</key><dict><key>TestStream</key>` + socketSpec("stream", port) + `</dict></dict></plist>`
	file := tmp + "/test.plist"
	if e = os.WriteFile(file, []byte(xml), 0644); e != nil {
		t.Fatal(e)
	}
	if out, e := exec.Command("/bin/launchctl", "bootstrap", domain, file).CombinedOutput(); e != nil {
		t.Fatalf("%s: %v", out, e)
	}
	defer exec.Command("/bin/launchctl", "bootout", domain+"/"+label).Run()
	for i := 0; i < 2; i++ {
		c, e := net.DialTimeout("tcp4", "127.0.0.1:"+port, 3*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(12 * time.Second))
		reply, e := limitedLines(c)
		c.Close()
		if e != nil || reply != "activated" {
			t.Fatal("socket did not survive worker exit", e, reply)
		}
	}
}

func TestTransparentHTTPSAcrossProxy(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "from protected origin") }))
	defer origin.Close()
	requests := make(chan string, 1)
	cfg := proxyFixture(t, "http", func(n net.Conn) {
		req, err := http.ReadRequest(bufio.NewReader(n))
		if err != nil {
			return
		}
		requests <- req.Host
		dst, err := net.Dial("tcp", origin.Listener.Addr().String())
		if err != nil {
			return
		}
		defer dst.Close()
		io.WriteString(n, "HTTP/1.1 200 OK\r\n\r\n")
		pipe(n, dst)
	})
	// Unix sockets have a short pathname limit on Darwin.
	tmp, err := os.MkdirTemp("/tmp", "pg-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp)
	path := tmp + "/relay"
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	g := &gate{flows: make(map[net.Conn]bool), deadline: time.Now().Add(time.Minute)}
	go accept(listener, func(n net.Conn) { forward(n, cfg, g, func() bool { return true }, make(chan struct{}, 1)) })
	for _, open := range []bool{true, false} {
		if !open {
			g.closeAll()
		}
		a, b := net.Pipe()
		a.SetDeadline(time.Now().Add(5 * time.Second))
		b.SetDeadline(time.Now().Add(5 * time.Second))
		go func() {
			defer b.Close()
			host, hello := inspect(b)
			if host != "" {
				bridge(b, path, host, hello, false)
			}
		}()
		// Pin the ephemeral origin certificate; its test SAN is unrelated to the routed name.
		client := tls.Client(a, &tls.Config{ServerName: "api.service.example", InsecureSkipVerify: true, VerifyConnection: func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) == 0 || !s.PeerCertificates[0].Equal(origin.Certificate()) {
				return fmt.Errorf("test origin certificate mismatch")
			}
			return nil
		}})
		err = client.Handshake()
		if !open {
			a.Close()
			if err == nil {
				t.Fatal("blocked gate forwarded TLS")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(client, "GET / HTTP/1.1\r\nHost: api.service.example\r\nConnection: close\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(client), nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		a.Close()
		if err != nil || string(body) != "from protected origin" || <-requests != "api.service.example:443" {
			t.Fatal("incorrect proxy response", err)
		}
	}
}

func TestSystemZoneIsOwnedOnlyByLegacyInstallation(t *testing.T) {
	const original = "Asia/Yerevan"
	const applied = "Europe/Berlin"
	const next = "America/New_York"
	fresh := Installation{Zone: applied}
	legacy := Installation{Original: original, Zone: applied}
	upgraded := legacy
	upgraded.rememberLegacyZone()
	upgraded.Zone = next
	upgraded.rememberLegacyZone()
	interrupted := legacy
	interrupted.Pending = next
	cases := []struct {
		name        string
		record      Installation
		local, want string
	}{
		{"fresh independent zone", fresh, original, ""},
		{"fresh matching zone", fresh, applied, ""},
		{"old install", legacy, applied, original},
		{"already restored", legacy, original, ""},
		{"changed by user", legacy, "Asia/Tokyo", ""},
		{"preserve old ownership after proxy edit", upgraded, applied, original},
		{"new proxy zone is not owned", upgraded, next, ""},
		{"interrupted old apply", interrupted, next, original},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.record.previousZone(c.local); got != c.want {
				t.Fatalf("restore %q, want %q", got, c.want)
			}
		})
	}
}

func TestTimeZoneScopeTransitions(t *testing.T) {
	const local = "Asia/Yerevan"
	const first = "Europe/Berlin"
	const second = "America/New_York"
	zone := local
	state := Installation{Zone: first}
	var journal Installation
	var calls []string
	set := func(z string) error { calls = append(calls, z); zone = z; return nil }
	store := func(s Installation) error { journal = s; return nil }
	apply := func(wide bool, target string) {
		t.Helper()
		if e := applyTimeZone(&state, target, wide, zone, set, store); e != nil {
			t.Fatal(e)
		}
		state.Zone = target
	}
	apply(false, first)
	if len(calls) != 0 || state.Original != "" {
		t.Fatal("application mode changed Mac")
	}
	apply(true, first)
	apply(true, first)
	apply(true, second)
	if len(calls) != 2 || state.Original != local || journal.previousZone(second) != local {
		t.Fatal("lost baseline on reapply")
	}
	apply(false, second)
	if zone != local || state.SystemWide || state.Original != "" {
		t.Fatal("did not restore previous Mac zone")
	}
	apply(true, first)
	zone = "Asia/Tokyo"
	apply(false, first)
	if zone != "Asia/Tokyo" {
		t.Fatal("overwrote a manual system change")
	}
	apply(true, first)
	zone = "Europe/London"
	apply(true, second)
	apply(false, second)
	if zone != "Europe/London" {
		t.Fatal("did not preserve newer baseline")
	}
	state = Installation{Zone: first}
	if e := applyTimeZone(&state, first, true, local, func(string) error { return fmt.Errorf("systemsetup failed") }, store); e == nil || journal.previousZone(first) != local {
		t.Fatal("lost interrupted change journal")
	}
	state = Installation{Zone: first}
	if e := applyTimeZone(&state, first, true, local, func(string) error { t.Fatal("timezone changed before journal persisted"); return nil }, func(Installation) error { return fmt.Errorf("disk full") }); e == nil {
		t.Fatal("journal failure ignored")
	}
}
