package main

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"time"
)

// Authoritative local-only responder. No code path here performs upstream DNS.
func answer(q []byte) []byte {
	if len(q) < 17 || q[2]&0xf8 != 0 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return nil
	}
	var labels []string
	i := 12
	for {
		if i >= len(q) {
			return nil
		}
		n := int(q[i])
		i++
		if n == 0 {
			break
		}
		if n > 63 || i+n > len(q) || i > 267 {
			return nil
		}
		labels = append(labels, string(q[i:i+n]))
		i += n
	}
	if i+4 > len(q) {
		return nil
	}
	typ := binary.BigEndian.Uint16(q[i:])
	class := binary.BigEndian.Uint16(q[i+2:])
	name := strings.Join(labels, ".")
	reply := append([]byte{}, q[:i+4]...)
	reply[2] = 0x84 | (q[2] & 1)
	reply[3] = 0
	clear(reply[6:12])
	if (!protected(name) && canonical(name) != checkHost) || class != 1 {
		reply[3] = 5
		return reply
	}
	if typ == 1 {
		reply[7] = 1
		reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4)
		reply = append(reply, net.ParseIP(localIP).To4()...)
	}
	// AAAA, HTTPS/SVCB and other types receive authoritative NODATA.
	return reply
}
func udpDNS(s *net.UDPConn) error {
	buf := make([]byte, 4096)
	for {
		n, a, e := s.ReadFromUDP(buf)
		if e != nil {
			return e
		}
		if b := answer(buf[:n]); b != nil {
			_, _ = s.WriteToUDP(b, a)
		}
	}
}
func tcpDNS(c net.Conn) {
	c.SetDeadline(time.Now().Add(5 * time.Second))
	var size [2]byte
	if _, e := io.ReadFull(c, size[:]); e != nil {
		return
	}
	n := binary.BigEndian.Uint16(size[:])
	if n > 4096 {
		return
	}
	b := make([]byte, n)
	if _, e := io.ReadFull(c, b); e != nil {
		return
	}
	r := answer(b)
	if r == nil {
		return
	}
	binary.BigEndian.PutUint16(size[:], uint16(len(r)))
	_, _ = c.Write(append(size[:], r...))
}
