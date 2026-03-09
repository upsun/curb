//go:build linux

package sandbox

import (
	"fmt"
	"os"

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

// SendFD sends a file descriptor over a Unix socket using SCM_RIGHTS.
func SendFD(conn *os.File, fd int) error {
	rights := unix.UnixRights(fd)
	return unix.Sendmsg(int(conn.Fd()), []byte{0}, rights, nil, 0)
}

// RecvFD receives a file descriptor from a Unix socket using SCM_RIGHTS.
func RecvFD(conn *os.File) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(int(conn.Fd()), buf, oob, 0)
	if err != nil {
		return -1, fmt.Errorf("recvmsg: %w", err)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, fmt.Errorf("parsing control message: %w", err)
	}
	for _, msg := range msgs {
		fds, err := unix.ParseUnixRights(&msg)
		if err == nil && len(fds) > 0 {
			return fds[0], nil
		}
	}
	return -1, fmt.Errorf("no file descriptors received")
}
