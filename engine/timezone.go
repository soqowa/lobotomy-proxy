package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The clock is a separate setting: profile removal must not discard its rollback record.
const zoneFile = stateDir + "/timezone.json"

func saveClock(s Installation) error {
	b, e := json.Marshal(Installation{UID: s.UID, Zone: s.Zone, Original: s.Original, Pending: s.Pending, LegacyApplied: s.LegacyApplied, SystemWide: s.SystemWide})
	if e != nil {
		return e
	}
	return atomicFile(zoneFile, b, 0644)
}
func clockState(legacy Installation) (Installation, error) {
	b, e := os.ReadFile(zoneFile)
	if os.IsNotExist(e) {
		return legacy, nil
	}
	if e != nil {
		return Installation{}, e
	}
	var s Installation
	e = json.Unmarshal(b, &s)
	return s, e
}
func detachClock(s *Installation) error {
	if s.Original == "" && !s.SystemWide && s.Pending == "" {
		return nil
	}
	if absent(zoneFile) {
		s.rememberLegacyZone()
		if e := saveClock(*s); e != nil {
			return e
		}
	}
	s.Original = ""
	s.Pending = ""
	s.SystemWide = false
	s.LegacyApplied = ""
	return persist(*s)
}
func setClock(uid int, zone string, restore bool) error {
	lock, e := exclusive()
	if e != nil {
		return e
	}
	defer lock.Close()
	s, e := loadInstall()
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	if uid < 501 || s.UID != 0 && s.UID != uid {
		return errors.New("не удалось подтвердить владельца настройки")
	}
	if e = detachClock(&s); e != nil {
		return e
	}
	ledger, e := clockState(Installation{UID: uid})
	if e != nil {
		return e
	}
	if ledger.UID != uid {
		return errors.New("настройка пояса принадлежит другому пользователю")
	}
	current := currentZone()
	if !safeZone(current) {
		return errors.New("не удалось прочитать часовой пояс Mac")
	}
	if restore {
		if previous := ledger.previousZone(current); previous != "" {
			if e = changeZone(previous); e != nil {
				return e
			}
		}
		if absent(zoneFile) {
			return nil
		}
		return os.Remove(zoneFile)
	}
	if !safeZone(zone) {
		return errors.New("неверный пояс выхода")
	}
	if e = applyTimeZone(&ledger, zone, true, current, changeZone, saveClock); e != nil {
		return e
	}
	ledger.Zone = zone
	return saveClock(ledger)
}

var zoneAliases = sync.OnceValue(func() map[string]string {
	result := map[string]string{}
	data, err := os.ReadFile("/var/db/timezone/zoneinfo/tzdata.zi")
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && (f[0] == "L" || f[0] == "Link") {
			result[f[2]] = f[1]
		}
	}
	return result
})

func zoneName(z string) string {
	aliases := zoneAliases()
	for range 16 {
		next := aliases[z]
		if next == "" {
			break
		}
		z = next
	}
	return z
}
func zoneEqual(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	if !safeZone(a) || !safeZone(b) {
		return false
	}
	if zoneName(a) == zoneName(b) {
		return true
	}
	root := "/var/db/timezone/zoneinfo"
	x, e := filepath.EvalSymlinks(filepath.Join(root, a))
	if e != nil {
		return false
	}
	y, e := filepath.EvalSymlinks(filepath.Join(root, b))
	if e != nil {
		return false
	}
	if x == y {
		return true
	}
	ix, e := os.Stat(x)
	if e != nil {
		return false
	}
	iy, e := os.Stat(y)
	return e == nil && os.SameFile(ix, iy)
}
func zoneFromPath(p string) string {
	_, z, ok := strings.Cut(p, "/zoneinfo/")
	if !ok || !safeZone(z) {
		return ""
	}
	return z
}
func currentZone() string {
	if p, e := os.Readlink("/etc/localtime"); e == nil {
		if z := zoneFromPath(p); z != "" {
			return z
		}
	}
	if p, e := filepath.EvalSymlinks("/etc/localtime"); e == nil {
		return zoneFromPath(p)
	}
	return ""
}
func waitForZone(z string, read func() string, until time.Time, delay time.Duration) bool {
	for {
		if zoneEqual(read(), z) {
			return true
		}
		if !time.Now().Before(until) {
			return false
		}
		time.Sleep(delay)
	}
}
func changeZone(z string) error {
	if !safeZone(z) {
		return errors.New("некорректный часовой пояс")
	}
	cmd := exec.Command("/usr/sbin/systemsetup", "-settimezone", z)
	_, err := cmd.CombinedOutput()
	if waitForZone(z, currentZone, time.Now().Add(8*time.Second), 100*time.Millisecond) {
		return nil
	}
	if data, queryErr := exec.Command("/usr/sbin/systemsetup", "-gettimezone").Output(); queryErr == nil {
		_, actual, found := strings.Cut(strings.TrimSpace(string(data)), ":")
		if found && zoneEqual(strings.TrimSpace(actual), z) {
			return nil
		}
	}
	if err != nil {
		return fmt.Errorf("смена часового пояса: %w", err)
	}
	return fmt.Errorf("запрошен пояс %s, macOS сообщает %s. Повторите проверку в «Подключении»", z, currentZone())
}
