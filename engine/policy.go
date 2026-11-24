package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

//go:embed catalog.json
var catalogData []byte

type Application struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Adapter string `json:"adapter"`
	Port    int    `json:"port"`
}

var catalog struct {
	Apps []Application `json:"apps"`
}

func init() {
	if err := json.Unmarshal(catalogData, &catalog); err != nil {
		panic(err)
	}
}

type AppRule struct {
	ID      string   `json:"id"`
	All     bool     `json:"all"`
	Domains []string `json:"domains"`
}
type Policy struct {
	Domains      []string  `json:"domains"`
	Applications []AppRule `json:"applications"`
}
type Transition struct {
	OldBlock  string   `json:"oldBlock"`
	OldRules  []string `json:"oldRules"`
	OldDigest string   `json:"oldDigest"`
	OldPlist  string   `json:"oldPlist"`
}

var activePolicy Policy // set once before starting listeners in this process
func normalized(in []string) ([]string, error) {
	if len(in) > 256 {
		return nil, errors.New(message("too many domains"))
	}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		h := canonical(strings.TrimPrefix(strings.TrimSpace(raw), "*."))
		if !validName(h) || !strings.Contains(h, ".") || net.ParseIP(h) != nil || h == checkHost || strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".local") || strings.ContainsAny(h, "/\\") {
			return nil, fmt.Errorf(message("invalid domain: %q"), raw)
		}
		out = append(out, h)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}
func (p *Policy) validate() error {
	var e error
	p.Domains, e = normalized(p.Domains)
	if e != nil {
		return e
	}
	if p.Applications == nil {
		p.Applications = []AppRule{}
	}
	seen := map[string]bool{}
	for i := range p.Applications {
		r := &p.Applications[i]
		if seen[r.ID] || !slices.ContainsFunc(catalog.Apps, func(a Application) bool { return a.ID == r.ID }) {
			return errors.New(message("unsupported or duplicate app"))
		}
		seen[r.ID] = true
		r.Domains, e = normalized(r.Domains)
		if e != nil {
			return e
		}
	}
	slices.SortFunc(p.Applications, func(a, b AppRule) int { return strings.Compare(a.ID, b.ID) })
	return nil
}
func matches(domains []string, host string) bool {
	host = canonical(host)
	if !validName(host) {
		return false
	}
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}
func (p Policy) allows(scope, host string, port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	if scope == "" {
		return port == 443 && matches(p.Domains, host)
	}
	for _, r := range p.Applications {
		if r.ID != scope {
			continue
		}
		if !r.All {
			return matches(r.Domains, host)
		}
		if ip, e := netip.ParseAddr(host); e == nil {
			return ip.IsGlobalUnicast() && !ip.IsPrivate()
		}
		return validName(host) && strings.Contains(host, ".") && !strings.HasSuffix(host, ".local") && !strings.HasSuffix(host, ".localhost")
	}
	return false
}
func (p Policy) stamp() string {
	data, _ := json.Marshal(p)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
func rules() []string { return append(slices.Clone(activePolicy.Domains), checkHost) }
func keptAliases(block string, domains []string) []string {
	var aliases []string
	for _, line := range strings.Split(block, "\n") {
		ip, host, ok := strings.Cut(line, " ")
		if ok && ip == localIP && matches(domains, host) && !slices.Contains(domains, host) {
			aliases = append(aliases, host)
		}
	}
	slices.Sort(aliases)
	return slices.Compact(aliases)
}

var activeAliases []string

func blockFor(domains []string, aliases ...string) string {
	var b strings.Builder
	b.WriteString(prefix)
	for _, h := range append(append(slices.Clone(domains), aliases...), checkHost) {
		fmt.Fprintf(&b, "%s %s\n", localIP, h)
	}
	b.WriteString(suffix)
	return b.String()
}
func hostBlock() string { return blockFor(activePolicy.Domains, activeAliases...) }
func ownedBlock(b []byte) (string, error) {
	a := bytes.Index(b, []byte(prefix))
	z := bytes.Index(b, []byte(suffix))
	if a < 0 && z < 0 {
		return "", nil
	}
	if a < 0 || z < a || (a > 0 && b[a-1] != '\n') || bytes.Count(b, []byte(prefix)) != 1 || bytes.Count(b, []byte(suffix)) != 1 {
		return "", errors.New(message("the Lobotomy Proxy section in hosts is damaged"))
	}
	return string(b[a : z+len(suffix)]), nil
}
func legacyPolicy() (Policy, string, error) {
	// Older installations didn't journal their domains. Recover the exact owned files.
	var p Policy
	b, e := os.ReadFile(hostsFile)
	if e != nil {
		return p, "", e
	}
	block, e := ownedBlock(b)
	if e != nil || block == "" {
		return p, "", errors.New(message("the previous installation’s section was not found"))
	}
	names, e := os.ReadDir(resolver)
	if e != nil {
		return p, "", e
	}
	for _, n := range names {
		d := n.Name()
		if d == checkHost || !validName(d) {
			continue
		}
		data, e := os.ReadFile(filepath.Join(resolver, d))
		if e == nil && string(data) == splitRule(d) && strings.Contains(block, "\n"+localIP+" "+d+"\n") {
			p.Domains = append(p.Domains, d)
		}
	}
	if e = p.validate(); e != nil {
		return p, "", e
	}
	for _, line := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(block, prefix), suffix), "\n") {
		if line == "" {
			continue
		}
		ip, d, ok := strings.Cut(line, " ")
		if !ok || ip != localIP || (d != checkHost && !matches(p.Domains, d)) {
			return p, "", errors.New(message("unrecognized entries in the previous hosts section"))
		}
	}
	return p, block, nil
}
func replaceHosts(path, old, next string, domains []string) error {
	if e := regular(path); e != nil {
		return e
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	present, e := ownedBlock(b)
	if e != nil {
		return e
	}
	if present != old && present != next {
		return errors.New(message("the hosts section was changed externally"))
	}
	others := string(b)
	if present != "" {
		others = strings.Replace(others, present, "", 1)
	}
	for _, line := range strings.Split(others, "\n") {
		f := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(f) > 1 {
			for _, h := range f[1:] {
				if matches(domains, h) || canonical(h) == checkHost && next != "" {
					return fmt.Errorf(message("an external hosts entry already exists for %s"), h)
				}
			}
		}
	}
	if present == next {
		return nil
	}
	var updated string
	if present != "" {
		updated = strings.Replace(string(b), present, next, 1)
	} else {
		if len(b) > 0 && b[len(b)-1] != '\n' {
			return errors.New(message("check the last line of the hosts file"))
		}
		updated = string(b) + next
	}
	st, e := os.Stat(path)
	if e != nil {
		return e
	}
	return atomicFile(path, []byte(updated), st.Mode().Perm())
}
