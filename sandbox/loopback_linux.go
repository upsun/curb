//go:build linux

package sandbox

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// bringUpLoopback brings up the loopback interface in an isolated net namespace.
func bringUpLoopback() error {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket for ioctl: %w", err)
	}
	defer func() { _ = unix.Close(sock) }()
	if err := setInterfaceUp(sock, "lo"); err != nil {
		return fmt.Errorf("bringing up lo: %w", err)
	}
	return nil
}

// setInterfaceUp brings a network interface up using ioctl SIOCSIFFLAGS.
func setInterfaceUp(sock int, name string) error {
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(sock, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("SIOCGIFFLAGS: %w", err)
	}
	flags := ifr.Uint16()
	ifr.SetUint16(flags | unix.IFF_UP | unix.IFF_RUNNING)
	if err := unix.IoctlIfreq(sock, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("SIOCSIFFLAGS: %w", err)
	}
	return nil
}
