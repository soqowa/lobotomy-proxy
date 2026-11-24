package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var stopped = errors.New("ClientHello captured")

type peek struct {
	net.Conn
	in io.Reader
}

func (p peek) Read(b []byte) (int, error)  { return p.in.Read(b) }
func (p peek) Write(b []byte) (int, error) { return len(b), nil }
func inspect(c net.Conn) (string, []byte) {
	var captured bytes.Buffer
	var name string
	in := io.TeeReader(io.LimitReader(c, 65536), &captured)
	t := tls.Server(peek{c, in}, &tls.Config{GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
		name = canonical(hi.ServerName)
		return nil, stopped
	}})
	if t.Handshake() != stopped || !protected(name) {
		return "", nil
	}
	return name, captured.Bytes()
}
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 1)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	<-done
	a.Close()
	b.Close()
	<-done
}
func limitedLines(c net.Conn) (string, error) {
	// Read one line without buffering subsequent application bytes.
	var b [1]byte
	line := make([]byte, 0, 96)
	for len(line) < 300 {
		if _, e := io.ReadFull(c, b[:]); e != nil {
			return "", e
		}
		if b[0] == '\n' {
			return string(line), nil
		}
		line = append(line, b[0])
	}
	return "", errors.New("line too long")
}
func bridge(client net.Conn, workerSocket string, host string, first []byte, pac bool) {
	remote, e := net.DialTimeout("unix", workerSocket, time.Second)
	if e != nil {
		return
	}
	defer remote.Close()
	remote.SetDeadline(time.Now().Add(12 * time.Second))
	if _, e = io.WriteString(remote, host+"\n"); e != nil {
		return
	}
	ans, e := limitedLines(remote)
	if e != nil || ans != "OK" {
		return
	}
	if pac {
		if _, e = io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); e != nil {
			return
		}
	}
	if len(first) > 0 {
		if _, e = remote.Write(first); e != nil {
			return
		}
	}
	client.SetDeadline(time.Time{})
	remote.SetDeadline(time.Time{})
	pipe(client, remote)
}
func browser(c net.Conn, workerSocket string) {
	c.SetDeadline(time.Now().Add(12 * time.Second))
	hdr := header(c)
	if len(hdr) == 0 {
		return
	}
	if bytes.HasPrefix(hdr, []byte("GET ")) && diagnostic(c, hdr, "Browser policy → local proxy") {
		return
	}
	line := strings.SplitN(string(hdr), "\r\n", 2)[0]
	fields := strings.Fields(line)
	if len(fields) != 3 || fields[0] != "CONNECT" {
		io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		return
	}
	h, p, e := net.SplitHostPort(fields[1])
	h = canonical(h)
	if e != nil || p != "443" || !protected(h) {
		io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		return
	}
	bridge(c, workerSocket, h, nil, true)
}
func accept(s net.Listener, fn func(net.Conn)) error {
	slots := make(chan struct{}, 128)
	for {
		c, e := s.Accept()
		if e != nil {
			return e
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { c.Close(); <-slots }(); fn(c) }()
		default:
			c.Close()
		}
	}
}
func prepareRunDir(uid int) error {
	dir := runDir(uid)
	if absent(dir) {
		if e := os.Mkdir(dir, 0700); e != nil {
			return e
		}
		return os.Chown(dir, uid, -1)
	}
	st, e := os.Lstat(dir)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return errors.New(message("invalid socket directory"))
	}
	return nil
}

const heartbeat = stateDir + "/filter.sock"

// Bind the privileged listener and create the root-owned health socket first.
// All protocol parsing and forwarding then run under the installing user's UID.
func dropPrivileges(uid int) error {
	group, e := exec.Command("/usr/bin/id", "-g", strconv.Itoa(uid)).Output()
	if e != nil {
		return e
	}
	gid, e := strconv.Atoi(strings.TrimSpace(string(group)))
	if e != nil || gid <= 0 {
		return errors.New(message("could not determine the user’s group"))
	}
	if e = syscall.Setgroups([]int{gid}); e != nil {
		return e
	}
	if e = syscall.Setgid(gid); e != nil {
		return e
	}
	return syscall.Setuid(uid)
}
func filter() error {
	s, e := loadInstall()
	if e != nil {
		return e
	}
	if s.Filter == nil {
		return errors.New(message("filter update required"))
	}
	activePolicy = *s.Filter
	activeAliases = s.HostAliases
	if !presentAlias() {
		if e = command("/sbin/ifconfig", "lo0", "alias", localIP, "netmask", "255.255.255.255"); e != nil {
			return e
		}
	}
	if e = prepareRunDir(s.UID); e != nil {
		return e
	}
	u, e := packetSocket("DNSPacket")
	if e != nil {
		return e
	}
	defer u.Close()
	type endpoint struct {
		network, addr string
		fn            func(net.Conn)
	}
	ch := make(chan error, 6+len(catalog.Apps))
	listeners := []net.Listener{}
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()
	methods := []endpoint{{"tcp4", localIP + ":17688", localCheck}, {"launchd", "DNSStream", tcpDNS}, {"tcp4", localIP + ":443", func(c net.Conn) {
		c.SetDeadline(time.Now().Add(12 * time.Second))
		h, b := inspect(c)
		if h != "" {
			bridge(c, socket(s.UID), h, b, false)
		}
	}}, {"launchd", "Browser", func(c net.Conn) { browser(c, socket(s.UID)) }}}
	// This socket is inside a root-owned directory and appears only after every listener binds.
	_ = os.Remove(heartbeat)
	methods = append(methods, endpoint{"unix", heartbeat, func(c net.Conn) {
		c.SetDeadline(time.Now().Add(time.Second))
		io.WriteString(c, "PG3 "+activePolicy.stamp()+"\n")
	}})
	for _, m := range methods {
		var l net.Listener
		if m.network == "launchd" {
			l, e = streamSocket(m.addr)
		} else {
			l, e = net.Listen(m.network, m.addr)
		}
		if e != nil {
			return e
		}
		listeners = append(listeners, l)
	}
	if e = os.Chmod(heartbeat, 0666); e != nil {
		return e
	}
	apps := make([]net.Listener, 0, len(catalog.Apps))
	for _, app := range catalog.Apps {
		l, e := streamSocket(app.ID)
		if e != nil {
			return e
		}
		listeners = append(listeners, l)
		apps = append(apps, l)
	}
	if e = dropPrivileges(s.UID); e != nil {
		return e
	}
	for i, app := range catalog.Apps {
		l := apps[i]
		go func() { ch <- serveApp(l, s.UID, app.ID) }()
	}
	go func() { ch <- udpDNS(u) }()
	for i, m := range methods {
		l := listeners[i]
		go func() { ch <- accept(l, m.fn) }()
	}
	return <-ch
}
func live() bool {
	c, e := net.DialTimeout("unix", heartbeat, 300*time.Millisecond)
	if e != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(300 * time.Millisecond))
	v, _ := limitedLines(c)
	return v == "PG3 "+activePolicy.stamp()
}
func systemDNS() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, "/usr/sbin/scutil", "--dns").Output()
	return e == nil && dnsOK(string(b))
}

type gate struct {
	sync.Mutex
	deadline time.Time
	flows    map[net.Conn]bool
}

func (g *gate) closeAll() {
	g.Lock()
	defer g.Unlock()
	g.deadline = time.Time{}
	for c := range g.flows {
		c.Close()
	}
}
func (g *gate) admit(c net.Conn) bool {
	g.Lock()
	defer g.Unlock()
	if time.Now().After(g.deadline) {
		return false
	}
	g.flows[c] = true
	return true
}
func (g *gate) forget(c net.Conn) { g.Lock(); defer g.Unlock(); delete(g.flows, c) }

type Event struct {
	State   string  `json:"state"`
	Message string  `json:"message"`
	Report  *Report `json:"report,omitempty"`
}

func emit(s, m string, r *Report) { _ = json.NewEncoder(os.Stdout).Encode(Event{s, m, r}) }
func forward(client net.Conn, c Config, g *gate, healthy func() bool, faults chan<- struct{}) {
	client.SetDeadline(time.Now().Add(12 * time.Second))
	line, e := limitedLines(client)
	scope, host, port := parseDestination(line)
	if e != nil || !activePolicy.allows(scope, host, port) || !launchPermissions.allowed(scope) || !healthy() || !g.admit(client) {
		return
	}
	defer g.forget(client)
	untrack := launchPermissions.track(scope, client)
	defer untrack()
	remote, e := c.dial(context.Background(), host, port)
	if errors.Is(e, errNoAddress) {
		return
	}
	if e != nil {
		g.closeAll()
		select {
		case faults <- struct{}{}:
		default:
		}
		return
	}
	defer remote.Close()
	if !g.admit(remote) {
		return
	}
	defer g.forget(remote)
	if _, e = io.WriteString(client, "OK\n"); e != nil {
		return
	}
	client.SetDeadline(time.Time{})
	pipe(client, remote)
}
func worker(c Config) error {
	uid := os.Getuid()
	s, e := loadInstall()
	if e != nil || !s.Ready || s.UID != uid {
		return errors.New(message("macOS rules are not installed yet"))
	}
	if s.Filter == nil {
		return errors.New(message("apply the updated filter"))
	}
	activePolicy = *s.Filter
	activeAliases = s.HostAliases
	if !live() {
		return errors.New(message("system service unavailable"))
	}
	// Lock the stable directory inode instead of racing another worker's stale socket cleanup.
	directory, e := os.Open(runDir(uid))
	if e != nil {
		return e
	}
	defer directory.Close()
	if e = syscall.Flock(int(directory.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return errors.New(message("forwarding is already running in another window"))
	}
	_ = os.Remove(socket(uid))
	l, e := net.Listen("unix", socket(uid))
	if e != nil {
		return e
	}
	defer l.Close()
	g := &gate{flows: make(map[net.Conn]bool)}
	faults := make(chan struct{}, 1)
	go func() {
		_ = accept(l, func(client net.Conn) {
			forward(client, c, g, func() bool { return filesOK(s) && live() && systemDNS() }, faults)
		})
	}()
	type result struct {
		r     Report
		e     error
		epoch int
	}
	rc := make(chan result, 1)
	epoch := 0
	checking := false
	next := time.Time{}
	last := ""
	show := func(state, msg string, r *Report) {
		if state+msg != last || r != nil {
			emit(state, msg, r)
			last = state + msg
		}
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var first = true
	for {
		if !first {
			<-tick.C
		}
		first = false
		select {
		case <-faults:
			epoch++
			g.closeAll()
			next = time.Now().Add(2 * time.Second)
			show("blocked", message("The proxy rejected the connection. Forwarding is blocked."), nil)
		default:
		}
		ok := filesOK(s) && live() && systemDNS()
		if !ok {
			g.closeAll()
			epoch++
			show("blocked", message("Forwarding is blocked. Check the service and domain DNS rules."), nil)
		}
		select {
		case res := <-rc:
			checking = false
			if ok && res.epoch == epoch && res.e == nil && zoneEqual(res.r.Zone, s.Zone) {
				g.Lock()
				g.deadline = time.Now().Add(70 * time.Second)
				g.Unlock()
				show("passing", message("Filter route verified"), &res.r)
			} else if ok {
				g.closeAll()
				msg := message("The exit time zone changed.")
				if res.e != nil {
					msg = res.e.Error()
				}
				show("blocked", msg, nil)
			}
		default:
		}
		g.Lock()
		expired := !g.deadline.IsZero() && time.Now().After(g.deadline)
		g.Unlock()
		if expired {
			g.closeAll()
			show("blocked", message("The verification result expired."), nil)
		}
		if ok && !checking && time.Now().After(next) {
			checking = true
			next = time.Now().Add(40 * time.Second)
			stamp := epoch
			go func() { r, e := probe(c); rc <- result{r, e, stamp} }()
		}
	}
}
func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	var e error
	switch os.Args[1] {
	case "probe", "dns-check", "worker", "relay-worker":
		// Parent closes stdin on quit or crash. A worker must never outlive that capability.
		br := bufio.NewReader(os.Stdin)
		var line []byte
		var err error
		if os.Args[1] == "relay-worker" {
			if len(os.Args) != 3 {
				os.Exit(2)
			}
			fd, fe := strconv.Atoi(os.Args[2])
			if fe != nil || fd < 3 {
				os.Exit(2)
			}
			file := os.NewFile(uintptr(fd), "credentials")
			if file == nil {
				os.Exit(2)
			}
			line, err = io.ReadAll(io.LimitReader(file, 4096))
			file.Close()
		} else {
			line, err = br.ReadBytes('\n')
		}
		if err != nil && len(line) == 0 {
			e = err
			break
		}
		var c Config
		if e = json.Unmarshal(line, &c); e != nil {
			break
		}
		if e = c.validate(); e != nil {
			break
		}
		if c.DNSMode == "berlin" {
			c.resolver = c.newDNSClient()
		}
		if os.Args[1] == "dns-check" {
			var result []DNSObservation
			result, e = checkDNS(c)
			if e == nil {
				e = json.NewEncoder(os.Stdout).Encode(result)
			}
		} else if os.Args[1] == "probe" {
			var r Report
			r, e = probe(c)
			if e == nil {
				emit("tested", message("Exit verified"), &r)
			}
		} else {
			go func() { launchPermissions.read(br); os.Exit(0) }()
			go launchPermissions.monitor()
			emit("checking", message("Checking the system route"), nil)
			e = worker(c)
		}
	case "install":
		if len(os.Args) != 6 {
			os.Exit(2)
		}
		var uid int
		var p Policy
		uid, e = strconv.Atoi(os.Args[2])
		if e == nil {
			e = json.Unmarshal([]byte(os.Args[5]), &p)
		}
		if e == nil {
			switch os.Args[4] {
			case "keep", "application", "system":
				if os.Args[4] == "system" {
					e = setClock(uid, os.Args[3], false)
				}
				if e == nil {
					e = install(uid, os.Args[3], p)
				}
			default:
				e = errors.New(message("invalid time zone mode"))
			}
		}
	case "refresh-preferences":
		if len(os.Args) != 3 {
			os.Exit(2)
		}
		s, err := loadInstall()
		if os.Geteuid() != 0 || err != nil || s.UID < 501 || strconv.Itoa(s.UID) != os.Args[2] {
			e = errors.New(message("could not verify ownership of the system rules"))
		} else {
			e = command("/usr/bin/mcxrefresh", "-u", os.Args[2])
		}
	case "set-zone":
		if len(os.Args) != 4 {
			os.Exit(2)
		}
		var uid int
		uid, e = strconv.Atoi(os.Args[2])
		if e == nil {
			e = setClock(uid, os.Args[3], false)
		}
	case "restore-zone":
		if len(os.Args) != 3 {
			os.Exit(2)
		}
		var uid int
		uid, e = strconv.Atoi(os.Args[2])
		if e == nil {
			e = setClock(uid, "", true)
		}
	case "rollback-filter":
		e = uninstall()
	case "rollback":
		prior, err := loadInstall()
		ledger, ze := clockState(prior)
		if err != nil && !os.IsNotExist(err) {
			e = err
			break
		}
		if ze != nil {
			e = ze
			break
		}
		e = uninstall()
		if e == nil && ledger.UID >= 501 {
			e = setClock(ledger.UID, "", true)
		}
	case "filter":
		e = filter()
	case "catalog":
		os.Stdout.Write(catalogData)
	case "normalize":
		var p Policy
		e = json.NewDecoder(os.Stdin).Decode(&p)
		if e == nil {
			e = p.validate()
		}
		if e == nil {
			e = json.NewEncoder(os.Stdout).Encode(p)
		}
	case "system":
		s, err := loadInstall()
		legacy := err == nil && s.Filter == nil
		if legacy {
			if p, _, e := legacyPolicy(); e == nil {
				activePolicy = p
			}
		} else if s.Filter != nil {
			activePolicy = *s.Filter
			activeAliases = s.HostAliases
		}
		zone := currentZone()
		clock, ce := clockState(s)
		if ce != nil {
			e = ce
			break
		}
		needsAdmin := os.IsPermission(err) && !absent(jobFile)
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"installed": err == nil || needsAdmin, "needsAdmin": needsAdmin, "previousZone": clock.previousZone(zone), "ready": s.Ready, "ownsZone": clock.SystemWide || clock.Original != "", "installedDigest": s.Digest, "policy": activePolicy, "legacyFilter": legacy, "systemWide": clock.SystemWide, "proxyZone": s.Zone, "filter": live(), "rulesReady": err == nil && s.Ready && rulesOnDisk(), "clockReady": !clock.SystemWide || zoneEqual(zone, clock.Zone), "files": err == nil && filesOK(s), "dns": err == nil && systemDNS(), "zone": zone})
	default:
		os.Exit(2)
	}
	if e != nil {
		emit("error", e.Error(), nil)
		os.Exit(1)
	}
}
