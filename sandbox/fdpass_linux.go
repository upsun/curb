//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// CreateSocketPair creates a Unix socketpair for SCM_RIGHTS fd passing.
// The caller is responsible for closing both ends.
func CreateSocketPair() (parent, child *os.File, err error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("socketpair: %w", err)
	}
	parent = os.NewFile(uintptr(fds[0]), "socketpair-parent")
	child = os.NewFile(uintptr(fds[1]), "socketpair-child")
	return parent, child, nil
}

// FD tag bytes for multiplexing connections over a shared socketpair.
const (
	FDTagHTTP   byte = 0x00 // HTTP proxy connection.
	FDTagSOCKS5 byte = 0x01 // SOCKS5 proxy connection.
)

// SendFD sends a file descriptor over a Unix socket using SCM_RIGHTS.
// The tag byte identifies the connection type (FDTagHTTP, FDTagSOCKS5).
func SendFD(conn *os.File, fd int, tag byte) error {
	rights := unix.UnixRights(fd)
	err := unix.Sendmsg(int(conn.Fd()), []byte{tag}, rights, nil, 0)
	runtime.KeepAlive(conn)
	return err
}

// RecvFD receives a file descriptor and its tag byte from a Unix socket
// using SCM_RIGHTS.
func RecvFD(conn *os.File) (int, byte, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(int(conn.Fd()), buf, oob, 0)
	if err != nil {
		return -1, 0, fmt.Errorf("recvmsg: %w", err)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, 0, fmt.Errorf("parsing control message: %w", err)
	}
	for _, msg := range msgs {
		fds, err := unix.ParseUnixRights(&msg)
		if err == nil && len(fds) > 0 {
			// Close any extra fds beyond the first to avoid leaks.
			for _, extra := range fds[1:] {
				_ = unix.Close(extra)
			}
			runtime.KeepAlive(conn)
			return fds[0], buf[0], nil
		}
	}
	runtime.KeepAlive(conn)
	return -1, 0, fmt.Errorf("no file descriptors received")
}
