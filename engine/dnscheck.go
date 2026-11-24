package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

const diagnosticSite = "ip.net.coffee"

type DNSObservation struct {
	IP      string `json:"ip"`
	Country string `json:"country_code"`
	City    string `json:"city"`
}

// Generate fresh records exactly as the site's browser test does. Pixel delivery is optional:
// the authoritative nameserver records the recursive lookup even if it returns no address.
func checkDNS(c Config) ([]DNSObservation, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	b := make([]byte, 12)
	if _, e := rand.Read(b); e != nil {
		return nil, e
	}
	token := hex.EncodeToString(b)
	for i := 1; i <= 2; i++ {
		n, _ := c.dial(ctx, fmt.Sprintf("%s-%d.d.%s", token, i, diagnosticSite), 443)
		if n != nil {
			n.Close()
		}
	}
	var seen struct {
		IPs []string `json:"dns_servers"`
	}
	for i := 0; i < 4; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
		b, e := c.get(ctx, diagnosticSite, "/api/dns/result/"+token)
		if e != nil {
			return nil, e
		}
		if e = json.Unmarshal(b, &seen); e != nil {
			return nil, e
		}
		if len(seen.IPs) > 0 {
			break
		}
	}
	if len(seen.IPs) == 0 || len(seen.IPs) > 32 {
		return nil, errors.New(message("Net.Coffee could not verify the DNS address"))
	}
	var result []DNSObservation
	for _, s := range seen.IPs {
		ip, e := netip.ParseAddr(s)
		if e != nil {
			return nil, e
		}
		b, e := c.get(ctx, diagnosticSite, "/api/geoip/"+ip.String())
		if e != nil {
			return nil, e
		}
		var r DNSObservation
		if e = json.Unmarshal(b, &r); e != nil {
			return nil, e
		}
		r.IP = ip.String()
		result = append(result, r)
	}
	return result, nil
}
