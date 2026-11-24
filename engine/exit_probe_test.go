package main

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

type probeFixture struct {
	ip, cc, zone string
	overrides    map[string][]byte
	failed       map[string]error
	calls        map[string]int
}

func newProbeFixture() *probeFixture {
	return &probeFixture{"93.184.216.34", "DE", "Europe/Berlin", map[string][]byte{}, map[string]error{}, map[string]int{}}
}
func (f *probeFixture) get(_ context.Context, host, path string) ([]byte, error) {
	f.calls[host]++
	if err := f.failed[host]; err != nil {
		return nil, err
	}
	if reply, ok := f.overrides[host]; ok {
		return reply, nil
	}
	var s string
	switch host {
	case "www.cloudflare.com":
		s = fmt.Sprintf("ip=%s\nloc=%s\n", f.ip, f.cc)
	case "ifconfig.co":
		s = fmt.Sprintf(`{"ip":%q,"country_iso":%q,"time_zone":%q}`, f.ip, f.cc, f.zone)
	case "api.country.is":
		s = fmt.Sprintf(`{"ip":%q,"country":%q}`, f.ip, f.cc)
	case "ipwho.is":
		s = fmt.Sprintf(`{"success":true,"ip":%q,"country_code":%q,"timezone":{"id":%q}}`, f.ip, f.cc, f.zone)
	default:
		return nil, errors.New("unexpected provider " + host)
	}
	return []byte(s), nil
}

func TestExitProbeRateLimitAndRecovery(t *testing.T) {
	f := newProbeFixture()
	f.failed[ipWho.host] = &diagnosticHTTPError{ipWho.host, 429, "600"}
	p := exitProbe{get: f.get}
	before := time.Now()
	for i := 0; i < 2; i++ {
		r, e := p.check()
		if e != nil || r.Zone != f.zone || r.IP != f.ip {
			t.Fatalf("probe %d: %+v %v", i, r, e)
		}
	}
	if f.calls[ipWho.host] != 1 || f.calls[ifconfig.host] != 1 || p.limitedUntil[ipWho.host].Before(before.Add(10*time.Minute)) {
		t.Fatal("Retry-After or fallback not honored")
	}
	delete(f.failed, ipWho.host)
	p.zoneUntil = time.Now().Add(-time.Second)
	p.limitedUntil[ipWho.host] = time.Now().Add(-time.Second)
	if _, err := p.check(); err != nil || f.calls[ipWho.host] != 2 {
		t.Fatal("provider did not recover", err)
	}
}

func TestExitProbeBindsZoneToCurrentExit(t *testing.T) {
	f := newProbeFixture()
	p := exitProbe{get: f.get}
	if _, e := p.check(); e != nil {
		t.Fatal(e)
	}
	until := p.zoneUntil
	if _, e := p.check(); e != nil || p.zoneUntil != until || f.calls[ipWho.host] != 1 {
		t.Fatal("cache should only reuse zone", e)
	}
	f.ip = "93.184.216.35"
	f.zone = "Europe/Paris"
	f.cc = "FR"
	if r, e := p.check(); e != nil || r.Zone != "Europe/Paris" || f.calls[ipWho.host] != 2 {
		t.Fatal("new exit used stale zone", r, e)
	}
	p.zoneUntil = time.Now().Add(-time.Second)
	f.failed[ifconfig.host] = errors.New("unavailable")
	f.failed[ipWho.host] = errors.New("unavailable")
	if _, e := p.check(); e == nil {
		t.Fatal("expired metadata permitted unverified route")
	}
}

func TestExitProbeRejectsDisagreementAndInsufficientEvidence(t *testing.T) {
	for _, body := range []string{`{"ip":"93.184.216.35","country":"DE"}`, `{"ip":"93.184.216.34","country":"FR"}`} {
		f := newProbeFixture()
		p := exitProbe{get: f.get}
		if _, err := p.check(); err != nil {
			t.Fatal(err)
		}
		f.overrides[countryIS.host] = []byte(body)
		if _, err := p.check(); err == nil || f.calls[ipWho.host] != 1 {
			t.Fatal("conflict must block even with cached zone")
		}
	}
	f := newProbeFixture()
	p := exitProbe{get: f.get}
	if _, e := p.check(); e != nil {
		t.Fatal(e)
	}
	for _, host := range []string{countryIS.host, ipWho.host, ifconfig.host} {
		f.failed[host] = &diagnosticHTTPError{host, 429, "600"}
	}
	if _, e := p.check(); e == nil {
		t.Fatal("one observation and a cache entry must not pass")
	}
}

func TestExitProbeColdFallback(t *testing.T) {
	f := newProbeFixture()
	f.failed[cloudflareTrace.host] = &diagnosticHTTPError{cloudflareTrace.host, 429, "600"}
	p := exitProbe{get: f.get}
	if r, e := p.check(); e != nil || r.Zone != f.zone || f.calls[countryIS.host] != 1 {
		t.Fatal(r, e)
	}
	f = newProbeFixture()
	f.zone = "invalid/zone"
	p = exitProbe{get: f.get}
	if _, e := p.check(); e == nil {
		t.Fatal("invalid time zone accepted")
	}
}
