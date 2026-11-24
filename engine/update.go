package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

func install(uid int, zone string, desired Policy) error {
	if uid < 501 || !safeZone(zone) {
		return errors.New(message("check the user and the exit time zone"))
	}
	if e := desired.validate(); e != nil {
		return e
	}
	lock, e := exclusive()
	if e != nil {
		return e
	}
	defer lock.Close()
	self, e := os.Executable()
	if e != nil {
		return e
	}
	bin, e := os.ReadFile(self)
	if e != nil {
		return e
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(bin))
	s, e := loadInstall()
	if os.IsNotExist(e) {
		s = Installation{UID: uid, MadeResolver: absent(resolver), Zone: zone}
		for _, p := range []string{agent, jobFile, runDir(uid)} {
			if !absent(p) {
				return fmt.Errorf(message("path already in use: %s"), p)
			}
		}
		if presentAlias() {
			return errors.New(message("local IP address already in use"))
		}
	} else if e != nil {
		return e
	} else if s.UID != uid {
		return errors.New(message("another user owns the rules"))
	}
	if e = detachClock(&s); e != nil {
		return e
	}
	if s.MadeResolver && absent(resolver) {
		if e = os.Mkdir(resolver, 0755); e != nil {
			return e
		}
	}
	if s.MadeResolver {
		if e = readableDirectory(resolver); e != nil {
			return e
		}
	} else {
		st, e := os.Lstat(resolver)
		if e != nil || !st.IsDir() {
			return errors.New(message("nonstandard resolver directory"))
		}
	}
	if s.Updating != nil {
		if s.Filter == nil || s.Digest != digest {
			return errors.New(message("finish rolling back the interrupted update"))
		}
		if e = finishUpdate(&s, bin); e != nil {
			return e
		}
	}
	var old Policy
	var block, oldSpec string
	if s.Digest != "" {
		if s.Filter == nil {
			old, block, e = legacyPolicy()
			if e != nil {
				return e
			}
			oldSpec = string(legacyPlist())
		} else {
			old = *s.Filter
			block = blockFor(old.Domains, s.HostAliases...)
			oldSpec = string(plist())
		}
		spec, e := os.ReadFile(jobFile)
		if e != nil || string(spec) != oldSpec {
			return errors.New(message("the service definition was changed externally"))
		}
	}
	oldRules := []string{}
	if block != "" {
		oldRules = append(slices.Clone(old.Domains), checkHost)
	}
	for _, d := range append(slices.Clone(desired.Domains), checkHost) {
		if !slices.Contains(oldRules, d) && !absent(filepath.Join(resolver, d)) {
			return fmt.Errorf(message("a separate DNS configuration already exists for %s"), d)
		}
	}
	for _, d := range oldRules {
		data, e := os.ReadFile(filepath.Join(resolver, d))
		if e != nil || string(data) != splitRule(d) {
			return fmt.Errorf(message("the DNS configuration for %s was changed externally"), d)
		}
	}
	// Save both manifests before changing any owned file. A retry can finish either side of an atomic rename.
	s.Updating = &Transition{OldBlock: block, OldRules: oldRules, OldDigest: s.Digest, OldPlist: oldSpec}
	s.Ready = false
	s.HostAliases = keptAliases(block, desired.Domains)
	s.Filter = &desired
	s.Digest = digest
	if e = persist(s); e != nil {
		return e
	}
	if e = finishUpdate(&s, bin); e != nil {
		return e
	}
	return activateInstall(s, zone)
}
func finishUpdate(s *Installation, bin []byte) error {
	t := s.Updating
	activePolicy = *s.Filter
	activeAliases = s.HostAliases
	for _, d := range rules() {
		p := filepath.Join(resolver, d)
		if absent(p) {
			if e := atomicFile(p, []byte(splitRule(d)), 0644); e != nil {
				return e
			}
		} else {
			b, e := os.ReadFile(p)
			if e != nil || string(b) != splitRule(d) {
				return fmt.Errorf(message("DNS conflict for %s"), d)
			}
		}
	}
	if e := replaceHosts(hostsFile, t.OldBlock, hostBlock(), activePolicy.Domains); e != nil {
		return e
	}
	for _, d := range t.OldRules {
		if !slices.Contains(rules(), d) {
			if e := removeOwned(filepath.Join(resolver, d), []byte(splitRule(d))); e != nil {
				return e
			}
		}
	}
	oldBin, e := os.ReadFile(agent)
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	actual := fmt.Sprintf("%x", sha256.Sum256(oldBin))
	if e == nil && actual != s.Digest && actual != t.OldDigest {
		return errors.New(message("the service executable was changed externally"))
	}
	if actual != s.Digest {
		if e = atomicFile(agent, bin, 0755); e != nil {
			return e
		}
	}
	spec, e := os.ReadFile(jobFile)
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	if !bytes.Equal(spec, plist()) {
		if string(spec) != t.OldPlist {
			return errors.New(message("the service definition was changed externally"))
		}
		if e = atomicFile(jobFile, plist(), 0644); e != nil {
			return e
		}
	}
	if (t.OldDigest != s.Digest || !live()) && command("/bin/launchctl", "print", "system/"+job) == nil {
		if e = command("/bin/launchctl", "bootout", "system/"+job); e != nil {
			return e
		}
	}
	s.Updating = nil
	return persist(*s)
}
