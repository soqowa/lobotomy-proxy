package main

/*
#include <launch.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

static int take_socket(const char *name, int *out) {
    int *fds = NULL;
    size_t count = 0;
    int error = launch_activate_socket(name, &fds, &count);
    if (error) return error;
    if (count == 1) {
        *out = fds[0];
    } else {
        for (size_t i = 0; i < count; i++) close(fds[i]);
        error = EINVAL;
    }
    free(fds);
    return error;
}
*/
import "C"
import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

func activated(name string) (*os.File, error) {
	n := C.CString(name)
	defer C.free(unsafe.Pointer(n))
	var fd C.int
	if code := C.take_socket(n, &fd); code != 0 {
		return nil, fmt.Errorf("launchd %s: %w", name, syscall.Errno(code))
	}
	return os.NewFile(uintptr(fd), name), nil
}
func streamSocket(name string) (net.Listener, error) {
	f, e := activated(name)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return net.FileListener(f)
}
func packetSocket(name string) (*net.UDPConn, error) {
	f, e := activated(name)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	p, e := net.FilePacketConn(f)
	if e != nil {
		return nil, e
	}
	u, ok := p.(*net.UDPConn)
	if !ok {
		p.Close()
		return nil, fmt.Errorf("%s is not UDP", name)
	}
	return u, nil
}
func socketSpec(kind, port string) string {
	return "<dict><key>SockFamily</key><string>IPv4</string><key>SockNodeName</key><string>127.0.0.1</string><key>SockServiceName</key><string>" + port + "</string><key>SockType</key><string>" + kind + "</string></dict>"
}
