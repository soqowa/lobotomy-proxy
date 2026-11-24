package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Ask the AppKit supervisor about the current launch before admitting a scoped
// connection. The global domain route doesn't depend on an application launch.
type admissions struct {
	seq     atomic.Uint64
	mu      sync.Mutex
	pending map[uint64]chan bool
	flows   map[string]map[net.Conn]bool
	out     io.Writer
}

func newAdmissions(out io.Writer) *admissions {
	return &admissions{pending: map[uint64]chan bool{}, flows: map[string]map[net.Conn]bool{}, out: out}
}
func (a *admissions) read(r *bufio.Reader) {
	for {
		line, e := r.ReadBytes('\n')
		if e != nil {
			return
		}
		var result struct {
			ID uint64 `json:"zoneRequest"`
			OK bool   `json:"ok"`
		}
		if json.Unmarshal(line, &result) != nil {
			continue
		}
		a.mu.Lock()
		c := a.pending[result.ID]
		if c != nil {
			select {
			case c <- result.OK:
			default:
			}
		}
		a.mu.Unlock()
	}
}
func (a *admissions) allowed(scope string) bool {
	if scope == "" {
		return true
	}
	id := a.seq.Add(1)
	ch := make(chan bool, 1)
	a.mu.Lock()
	a.pending[id] = ch
	a.mu.Unlock()
	defer func() { a.mu.Lock(); delete(a.pending, id); a.mu.Unlock() }()
	if json.NewEncoder(a.out).Encode(struct {
		ID  uint64 `json:"zoneRequest"`
		App string `json:"app"`
	}{id, scope}) != nil {
		return false
	}
	select {
	case pass := <-ch:
		return pass
	case <-time.After(2 * time.Second):
		return false
	}
}
func (a *admissions) track(scope string, c net.Conn) func() {
	if scope == "" {
		return func() {}
	}
	a.mu.Lock()
	if a.flows[scope] == nil {
		a.flows[scope] = map[net.Conn]bool{}
	}
	a.flows[scope][c] = true
	a.mu.Unlock()
	return func() {
		a.mu.Lock()
		delete(a.flows[scope], c)
		if len(a.flows[scope]) == 0 {
			delete(a.flows, scope)
		}
		a.mu.Unlock()
	}
}
func (a *admissions) monitor() {
	for range time.Tick(time.Second) {
		a.mu.Lock()
		scopes := make([]string, 0, len(a.flows))
		for s := range a.flows {
			scopes = append(scopes, s)
		}
		a.mu.Unlock()
		for _, scope := range scopes {
			if !a.allowed(scope) {
				a.mu.Lock()
				for c := range a.flows[scope] {
					c.Close()
				}
				a.mu.Unlock()
			}
		}
	}
}

var launchPermissions = newAdmissions(os.Stdout)
