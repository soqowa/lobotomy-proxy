package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type diagnosticHTTPError struct {
	host       string
	status     int
	retryAfter string
}

func (e *diagnosticHTTPError) Error() string {
	return fmt.Sprintf(message("diagnostic service %s returned HTTP %d"), e.host, e.status)
}

func (e *diagnosticHTTPError) retryAt(now time.Time) time.Time {
	if seconds, err := strconv.ParseUint(e.retryAfter, 10, 32); err == nil && seconds > 0 {
		return now.Add(time.Duration(seconds) * time.Second)
	}
	if date, err := http.ParseTime(e.retryAfter); err == nil && date.After(now) {
		return date
	}
	return now.Add(time.Hour)
}

type exitObserver struct {
	host, path string
	read       func([]byte) (Report, error)
}

var cloudflareTrace = exitObserver{"www.cloudflare.com", "/cdn-cgi/trace", func(r []byte) (Report, error) {
	var report Report
	for _, line := range strings.Split(string(r), "\n") {
		k, v, _ := strings.Cut(line, "=")
		switch k {
		case "ip":
			report.IP = strings.TrimSpace(v)
		case "loc":
			report.Country = strings.TrimSpace(v)
		}
	}
	return report, nil
}}
var countryIS = exitObserver{"api.country.is", "/", func(r []byte) (Report, error) {
	var v struct{ IP, Country string }
	err := json.Unmarshal(r, &v)
	return Report{IP: v.IP, Country: v.Country}, err
}}
var ifconfig = exitObserver{"ifconfig.co", "/json", func(r []byte) (Report, error) {
	var v struct {
		IP      string
		Country string `json:"country_iso"`
		Zone    string `json:"time_zone"`
	}
	err := json.Unmarshal(r, &v)
	return Report{v.IP, v.Country, v.Zone}, err
}}
var ipWho = exitObserver{"ipwho.is", "/?fields=success,ip,country_code,timezone.id", func(r []byte) (Report, error) {
	var v struct {
		Success  bool
		IP       string
		Country  string `json:"country_code"`
		TimeZone struct{ ID string }
	}
	if err := json.Unmarshal(r, &v); err != nil {
		return Report{}, err
	}
	if !v.Success {
		return Report{}, errors.New(message("could not determine the exit time zone"))
	}
	return Report{v.IP, v.Country, v.TimeZone.ID}, nil
}}

// One instance belongs to one proxy configuration. Only the time zone may be reused;
// two independent HTTPS observers must see the same public IP and country on every check.
type exitProbe struct {
	get          func(context.Context, string, string) ([]byte, error)
	cached       Report
	zoneUntil    time.Time
	limitedUntil map[string]time.Time
}

func (p *exitProbe) check() (Report, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	now := time.Now()
	observers := []exitObserver{cloudflareTrace, countryIS, ipWho, ifconfig}
	if !now.Before(p.zoneUntil) {
		p.cached = Report{}
		observers[1], observers[2] = ipWho, countryIS
	}
	if p.limitedUntil == nil {
		p.limitedUntil = make(map[string]time.Time)
	}
	var result Report
	var failures []error
	observations := 0
	for _, s := range observers {
		if until := p.limitedUntil[s.host]; now.Before(until) {
			failures = append(failures, fmt.Errorf(message("waiting before retrying %s"), s.host))
			continue
		}
		if ctx.Err() != nil {
			return Report{}, ctx.Err()
		}
		// Leave room for another observer when a single endpoint stalls.
		lookup, stop := context.WithTimeout(ctx, 7*time.Second)
		if s.host == ifconfig.host {
			p.limitedUntil[s.host] = time.Now().Add(time.Minute)
		}
		reply, err := p.get(lookup, s.host, s.path)
		stop()
		if err != nil {
			var status *diagnosticHTTPError
			if errors.As(err, &status) && status.status == http.StatusTooManyRequests {
				if until := status.retryAt(time.Now()); until.After(p.limitedUntil[s.host]) {
					p.limitedUntil[s.host] = until
				}
			}
			failures = append(failures, err)
			continue
		}
		observed, err := s.read(reply)
		ip, parseErr := netip.ParseAddr(observed.IP)
		ip = ip.Unmap()
		if err != nil || parseErr != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.Zone() != "" ||
			len(observed.Country) != 2 || observed.Country == "XX" || strings.Trim(observed.Country, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
			failures = append(failures, fmt.Errorf(message("invalid exit data from %s"), s.host))
			continue
		}
		observed.IP = ip.String()
		if observations > 0 && (result.IP != observed.IP || result.Country != observed.Country ||
			(result.Zone != "" && observed.Zone != "" && !zoneEqual(result.Zone, observed.Zone))) {
			p.cached = Report{}
			p.zoneUntil = time.Time{}
			return Report{}, errors.New(message("diagnostic services reported different exits"))
		}
		if observed.IP != p.cached.IP || observed.Country != p.cached.Country {
			p.cached = Report{}
			p.zoneUntil = time.Time{}
		}
		observations++
		result.IP, result.Country = observed.IP, observed.Country
		if observed.Zone != "" {
			if !safeZone(observed.Zone) {
				return Report{}, errors.New(message("could not determine the exit time zone"))
			}
			result.Zone = observed.Zone
		}
		if observations >= 2 {
			if result.Zone != "" {
				p.cached = result
				p.zoneUntil = now.Add(time.Hour)
				return result, nil
			}
			if time.Now().Before(p.zoneUntil) {
				return p.cached, nil
			}
		}
	}
	if len(failures) > 0 {
		return Report{}, errors.Join(failures...)
	}
	return Report{}, errors.New(message("could not determine the exit time zone"))
}
