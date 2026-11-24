package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Opt-in network integration. Read credentials only from stdin of the compiled test binary.
// Use the production CONNECT handler and relay on temporary sockets without touching macOS policy.
func TestNetCoffeeBrowser(t *testing.T) {
	if os.Getenv("PG_LIVE_BROWSER") != "1" {
		t.Skip("requires an authenticated upstream proxy")
	}
	var c Config
	if err := json.NewDecoder(os.Stdin).Decode(&c); err != nil {
		t.Fatal("missing proxy configuration")
	}
	c.DNSMode = "berlin"
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	c.resolver = c.newDNSClient()
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	dir, err := os.MkdirTemp("/tmp", "pg-browser-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "relay")
	relay, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	pac, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pac.Close()
	activePolicy = Policy{Domains: []string{diagnosticSite}}
	g := &gate{deadline: time.Now().Add(2 * time.Minute), flows: map[net.Conn]bool{}}
	defer g.closeAll()
	faults := make(chan struct{}, 1)
	go accept(relay, func(conn net.Conn) { forward(conn, c, g, func() bool { return true }, faults) })
	go accept(pac, func(conn net.Conn) { browser(conn, path) })
	cmd := exec.CommandContext(ctx, "node", "Tests/net-coffee.cjs")
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "PG_DIAGNOSTIC_PROXY=http://"+pac.Addr().String(), "PG_TEST_PAC=1", "PG_TEST_ZONE=Europe/Berlin", "PG_TEST_DNS_CITY=Berlin", "PG_TEST_DNS_COUNTRY=DE")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Run(); err != nil {
		t.Fatal(err)
	}
}
