package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestBerlinDNSFailureDoesNotSendTargetToUpstream(t *testing.T) {
	target := make(chan string, 1)
	c := proxyFixture(t, "http", func(n net.Conn) {
		r, e := http.ReadRequest(bufio.NewReader(n))
		if e != nil {
			target <- e.Error()
			return
		}
		target <- r.Host
		fmt.Fprint(n, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
	})
	c.DNSMode = "berlin"
	conn, e := c.dial(context.Background(), "must-not-resolve.example", 443)
	if e == nil || conn != nil {
		t.Fatal("DNS failure accepted")
	}
	if got := <-target; got != berlinDoHIP+":443" {
		t.Fatalf("unexpected bootstrap: %v", got)
	}
	c.Address = ""
	if c.validate() == nil {
		t.Fatal("allowed a local bootstrap lookup")
	}
}

func TestDNSReplyFollowsOnlyQuestionAliases(t *testing.T) {
	host := dnsmessage.MustNewName("www.example.")
	alias := dnsmessage.MustNewName("pool.example.")
	foreign := dnsmessage.MustNewName("extra.example.")
	q := dnsmessage.Question{Name: host, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	header := func(name dnsmessage.Name) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: name, Class: q.Class}
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Questions: []dnsmessage.Question{q}, Answers: []dnsmessage.Resource{
		{Header: header(foreign), Body: &dnsmessage.AResource{A: [4]byte{2, 2, 2, 2}}},
		{Header: header(host), Body: &dnsmessage.CNAMEResource{CNAME: alias}},
		{Header: header(alias), Body: &dnsmessage.AResource{A: [4]byte{127, 79, 71, 1}}},
		{Header: header(alias), Body: &dnsmessage.AResource{A: [4]byte{8, 8, 4, 4}}},
	}}
	wire, _ := m.Pack()
	ips, e := dnsAddresses(wire, q)
	if e != nil || len(ips) != 1 || ips[0] != netip.MustParseAddr("8.8.4.4") {
		t.Fatalf("invalid A answer: %v %v", ips, e)
	}
	q.Type = dnsmessage.TypeAAAA
	if _, e = dnsAddresses(wire, q); e == nil {
		t.Fatal("accepted wrong question type")
	}
	m.Questions = []dnsmessage.Question{q}
	m.Answers = []dnsmessage.Resource{{Header: header(host), Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:4860:4860::8888").As16()}}}
	wire, _ = m.Pack()
	if ips, e = dnsAddresses(wire, q); e != nil || len(ips) != 1 || !ips[0].Is6() {
		t.Fatal(ips, e)
	}
}
