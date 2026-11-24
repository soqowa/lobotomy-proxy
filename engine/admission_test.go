package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"
)

func TestLaunchAdmission(t *testing.T) {
	qout, qin := io.Pipe()
	rout, rin := io.Pipe()
	defer qout.Close()
	defer qin.Close()
	defer rin.Close()
	defer rout.Close()
	a := newAdmissions(qin)
	go a.read(bufio.NewReader(rout))
	if !a.allowed("") {
		t.Fatal("domain route wrongly blocked")
	}
	for _, allowed := range []bool{false, true} {
		result := make(chan bool, 1)
		go func() { result <- a.allowed("fixture.app") }()
		var q struct {
			ID  uint64 `json:"zoneRequest"`
			App string `json:"app"`
		}
		if err := json.NewDecoder(qout).Decode(&q); err != nil || q.App != "fixture.app" {
			t.Fatal(q, err)
		}
		fmt.Fprintf(rin, "{\"zoneRequest\":%d,\"ok\":%t}\n", q.ID, allowed)
		if (<-result) != allowed {
			t.Fatal("admission mismatch")
		}
	}
}
func TestDelayedZoneConfirmation(t *testing.T) {
	count := 0
	ok := waitForZone("Europe/Berlin", func() string {
		count++
		if count > 2 {
			return "Europe/Berlin"
		}
		return "Asia/Yerevan"
	}, time.Now().Add(time.Second), time.Millisecond)
	if !ok || count != 3 {
		t.Fatal(ok, count)
	}
	if waitForZone("Europe/Berlin", func() string { return "Asia/Yerevan" }, time.Now(), 0) {
		t.Fatal("accepted wrong zone")
	}
	if !zoneEqual("US/Pacific", "America/Los_Angeles") {
		t.Fatal("failed valid IANA alias on macOS")
	}
}
