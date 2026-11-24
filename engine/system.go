package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const stateDir = "/private/var/db/local.proxyguard"
const stateFile = stateDir + "/state.json"
const agent = stateDir + "/proxyguard"
const job = "local.proxyguard.filter"
const jobFile = "/Library/LaunchDaemons/" + job + ".plist"
const resolver = "/etc/resolver"
const hostsFile = "/etc/hosts"
const localIP = "127.79.71.1"
const dnsPort = "17653"
const browserPort = "17687"
const prefix = "# BEGIN local.proxyguard\n"
const suffix = "# END local.proxyguard\n"

type Installation struct {
	HostAliases []string    `json:"hostAliases,omitempty"`
	UID         int         `json:"uid"`
	Filter      *Policy     `json:"filter,omitempty"`
	Updating    *Transition `json:"updating,omitempty"`
	// Preserve the on-disk ownership journal used by version 1.0 for rollback.
	SystemWide    bool   `json:"systemWide,omitempty"`
	Original      string `json:"original,omitempty"`
	LegacyApplied string `json:"legacyApplied,omitempty"`
	Pending       string `json:"pending,omitempty"`
	Zone          string `json:"zone"`
	Ready         bool   `json:"ready"`
	MadeResolver  bool   `json:"madeResolver"`
	Alias         bool   `json:"alias"`
	Digest        string `json:"digest"`
}

func splitRule(d string) string {
	return "# local.proxyguard\ndomain " + d + "\nnameserver 127.0.0.1\nport " + dnsPort + "\ntimeout 1\nsearch_order 1\n"
}
func atomicFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".proxyguard-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func command(path string, args ...string) error {
	cmd := exec.Command(path, args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", filepath.Base(path), args[0], err)
	}
	return nil
}

// Freeze the old applied zone before changing the independently pinned proxy zone.
func (s *Installation) rememberLegacyZone() {
	if s.Original != "" && s.LegacyApplied == "" {
		s.LegacyApplied = s.Zone
	}
}
func (s Installation) previousZone(current string) string {
	s.rememberLegacyZone()
	if current == "" || s.Original == "" || zoneEqual(current, s.Original) || !safeZone(s.Original) {
		return ""
	}
	if zoneEqual(current, s.LegacyApplied) || zoneEqual(current, s.Pending) {
		return s.Original
	}
	return ""
}

// Record both sides before changing macOS so retries and rollback can recover even
// if the process exits between systemsetup and the final state-file commit.
func applyTimeZone(s *Installation, target string, systemWide bool, current string, set func(string) error, save func(Installation) error) error {
	if !systemWide && !s.SystemWide {
		return nil
	}
	if !safeZone(current) || !safeZone(target) {
		return errors.New("не удалось проверить часовой пояс")
	}
	if systemWide {
		s.rememberLegacyZone()
		if s.Original == "" || (s.previousZone(current) == "" && !zoneEqual(current, s.Original)) {
			s.Original = current
		}
		s.SystemWide = true
		s.Pending = target
		if e := save(*s); e != nil {
			return e
		}
		if !zoneEqual(current, target) {
			if e := set(target); e != nil {
				return e
			}
		}
		s.LegacyApplied = target
	} else {
		if previous := s.previousZone(current); previous != "" {
			if e := set(previous); e != nil {
				return e
			}
		}
		s.Original = ""
		s.LegacyApplied = ""
		s.SystemWide = false
	}
	s.Pending = ""
	return nil
}
func loadInstall() (Installation, error) {
	var s Installation
	b, e := os.ReadFile(stateFile)
	if e == nil {
		e = json.Unmarshal(b, &s)
	}
	return s, e
}
func persist(s Installation) error { b, _ := json.Marshal(s); return atomicFile(stateFile, b, 0644) }
func runDir(uid int) string        { return "/private/var/run/local.proxyguard-" + strconv.Itoa(uid) }
func socket(uid int) string        { return runDir(uid) + "/worker.sock" }
func legacyPlist() []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Label</key><string>local.proxyguard.filter</string><key>ProgramArguments</key><array><string>/private/var/db/local.proxyguard/proxyguard</string><string>filter</string></array><key>Sockets</key><dict><key>Browser</key>` + socketSpec("stream", browserPort) + `<key>DNSStream</key>` + socketSpec("stream", dnsPort) + `<key>DNSPacket</key>` + socketSpec("dgram", dnsPort) + `</dict><key>KeepAlive</key><true/><key>RunAtLoad</key><true/><key>ThrottleInterval</key><integer>5</integer><key>Umask</key><integer>63</integer></dict></plist>
`)
}

func plist() []byte {
	var specs strings.Builder
	for _, a := range catalog.Apps {
		specs.WriteString("<key>" + a.ID + "</key>" + socketSpec("stream", strconv.Itoa(a.Port)))
	}
	return bytes.Replace(legacyPlist(), []byte("</dict><key>KeepAlive"), []byte(specs.String()+"</dict><key>KeepAlive"), 1)
}

// A private umask in the privileged staging process can narrow mkdir(0755) to 0700.
// Only adjust a real root-owned directory used by this installation.
func readableDirectory(path string) error {
	info, e := os.Lstat(path)
	if e != nil {
		return e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || st.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("некорректный владелец или права папки %s", path)
	}
	if info.Mode().Perm() == 0755 {
		return nil
	}
	return os.Chmod(path, 0755)
}
func exclusive() (*os.File, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("требуются права администратора")
	}
	if e := os.MkdirAll(stateDir, 0755); e != nil {
		return nil, e
	}
	if e := readableDirectory(stateDir); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(stateDir+"/lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("установка уже выполняется")
	}
	return f, nil
}
func regular(path string) error {
	s, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !s.Mode().IsRegular() {
		return fmt.Errorf("необычный тип файла %s", path)
	}
	return nil
}
func absent(path string) bool { _, e := os.Lstat(path); return os.IsNotExist(e) }
func presentAlias() bool {
	b, _ := exec.Command("/sbin/ifconfig", "lo0").Output()
	return strings.Contains(string(b), "inet "+localIP+" ")
}
func removeOwned(path string, want []byte) error {
	if absent(path) {
		return nil
	}
	if err := regular(path); err != nil {
		return err
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if !bytes.Equal(b, want) {
		return fmt.Errorf("файл изменён отдельно, сохранён: %s", path)
	}
	return os.Remove(path)
}
func activateInstall(s Installation, zone string) error {
	if s.MadeResolver {
		if e := readableDirectory(resolver); e != nil {
			return e
		}
	}
	s.rememberLegacyZone()
	if !rulesOnDisk() {
		return errors.New("файлы доменных правил изменились. Проверьте конфликт перед откатом")
	}
	bin, e := os.ReadFile(agent)
	if e != nil || fmt.Sprintf("%x", sha256.Sum256(bin)) != s.Digest {
		return errors.New("установленный обработчик не прошёл проверку")
	}
	spec, e := os.ReadFile(jobFile)
	if e != nil || !bytes.Equal(spec, plist()) {
		return errors.New("настройка службы изменена отдельно")
	}
	s.Alias = true
	s.Ready = false
	if e = persist(s); e != nil {
		return e
	}
	flushDNS()
	if command("/bin/launchctl", "print", "system/"+job) != nil {
		if e = command("/bin/launchctl", "bootstrap", "system", jobFile); e != nil {
			return errors.Join(e, errors.New("доменные правила сохранены, передача закрыта"))
		}
	} else if !live() {
		if e = command("/bin/launchctl", "kickstart", "-k", "system/"+job); e != nil {
			return e
		}
	}
	for end := time.Now().Add(8 * time.Second); !live() && time.Now().Before(end); {
		time.Sleep(150 * time.Millisecond)
	}
	if !live() {
		return errors.New("служба не смогла занять локальные порты")
	}

	s.Ready = true
	s.Zone = zone
	if e = persist(s); e != nil {
		return e
	}
	flushDNS()
	return nil
}
func flushDNS() {
	_ = command("/usr/bin/dscacheutil", "-flushcache")
	_ = command("/usr/bin/killall", "-HUP", "mDNSResponder")
}
func uninstallLocked(s Installation) error {
	var errs []error
	// First stop the listeners. Retain the journal until each owned change has been reconciled.
	if command("/bin/launchctl", "print", "system/"+job) == nil {
		if e := command("/bin/launchctl", "bootout", "system/"+job); e != nil {
			return e
		}
	}
	if s.Alias && presentAlias() {
		errs = append(errs, command("/sbin/ifconfig", "lo0", "-alias", localIP))
	}
	var policy Policy
	var block string
	if s.Filter == nil {
		var e error
		policy, block, e = legacyPolicy()
		if e != nil {
			return e
		}
	} else {
		policy = *s.Filter
		block = blockFor(policy.Domains, s.HostAliases...)
	}
	names := append(slices.Clone(policy.Domains), checkHost)
	spec := plist()
	if s.Filter == nil {
		spec = legacyPlist()
	}
	acceptedDigests := []string{s.Digest}
	if t := s.Updating; t != nil {
		names = append(names, t.OldRules...)
		acceptedDigests = append(acceptedDigests, t.OldDigest)
		b, e := os.ReadFile(hostsFile)
		if e != nil {
			return e
		}
		actual, e := ownedBlock(b)
		if e != nil {
			return e
		}
		if actual == t.OldBlock {
			block = t.OldBlock
		}
		if b, e := os.ReadFile(jobFile); e == nil && string(b) == t.OldPlist {
			spec = b
		}
	}
	if s.Filter == nil {
		// Persist the imported manifest before the first deletion so a partially completed legacy rollback can retry.
		s.Filter = &policy
		s.Updating = &Transition{OldBlock: block, OldRules: names, OldDigest: s.Digest, OldPlist: string(spec)}
		s.Ready = false
		if e := persist(s); e != nil {
			return e
		}
	}
	for _, d := range names {
		errs = append(errs, removeOwned(filepath.Join(resolver, d), []byte(splitRule(d))))
	}
	errs = append(errs, replaceHosts(hostsFile, block, "", nil), removeOwned(jobFile, spec))
	if b, e := os.ReadFile(agent); e == nil {
		if slices.Contains(acceptedDigests, fmt.Sprintf("%x", sha256.Sum256(b))) {
			errs = append(errs, os.Remove(agent))
		} else {
			errs = append(errs, errors.New("исполняемый файл службы изменён отдельно"))
		}
	} else if !os.IsNotExist(e) {
		errs = append(errs, e)
	}
	if s.MadeResolver {
		_ = os.Remove(resolver)
	}
	// Unlink only our fixed socket name. Its parent cannot be replaced by a non-root user.
	if st, e := os.Lstat(runDir(s.UID)); e == nil && st.IsDir() {
		if socketInfo, e := os.Lstat(socket(s.UID)); e == nil && socketInfo.Mode()&os.ModeSocket != 0 {
			errs = append(errs, os.Remove(socket(s.UID)))
		}
		if e := os.Remove(runDir(s.UID)); e != nil {
			errs = append(errs, errors.New("в рабочей папке остались файлы; они сохранены"))
		}
	}
	flushDNS()
	if e := errors.Join(errs...); e != nil {
		return e
	}
	if !absent(heartbeat) {
		errs = append(errs, os.Remove(heartbeat))
	}
	if e := errors.Join(errs...); e != nil {
		return e
	}
	return os.Remove(stateFile)
}
func uninstall() error {
	lock, e := exclusive()
	if e != nil {
		return e
	}
	defer lock.Close()
	s, e := loadInstall()
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if e = detachClock(&s); e != nil {
		return e
	}
	return uninstallLocked(s)
}
func filesOK(s Installation) bool {
	installed, e := loadInstall()
	if e != nil || !installed.Ready || installed.UID != s.UID || installed.Filter == nil || s.Filter == nil || installed.Filter.stamp() != s.Filter.stamp() || installed.Zone != s.Zone {
		return false
	}
	clock, e := clockState(installed)
	if e != nil || clock.SystemWide && !zoneEqual(currentZone(), clock.Zone) {
		return false
	}
	return rulesOnDisk()
}
func rulesOnDisk() bool {
	h, e := os.ReadFile(hostsFile)
	if e != nil || !bytes.Contains(h, []byte(hostBlock())) {
		return false
	}
	for _, d := range rules() {
		b, e := os.ReadFile(filepath.Join(resolver, d))
		if e != nil || string(b) != splitRule(d) {
			return false
		}
	}
	return true
}

// Every protected suffix must have a unique effective, local system resolver.
func dnsOK(b string) bool {
	found := map[string]int{}
	for _, block := range strings.Split(b, "resolver #") {
		domain := ""
		local := false
		port := false
		other := false
		for _, line := range strings.Split(block, "\n") {
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			switch {
			case k == "domain":
				domain = v
			case strings.HasPrefix(k, "nameserver["):
				if v == "127.0.0.1" {
					local = true
				} else {
					other = true
				}
			case k == "port":
				port = v == dnsPort
			}
		}
		if protected(domain) || domain == checkHost {
			if !local || other || !port {
				return false
			}
			found[domain]++
		}
	}
	for _, d := range rules() {
		if found[d] < 1 {
			return false
		}
	}
	return true
}
