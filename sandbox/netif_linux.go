//go:build linux

package sandbox

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tapDevicePath = "/dev/net/tun"
	tapName       = "eth0"

	// Child IP and gateway match QEMU user-mode networking conventions.
	childIP      = "10.0.2.15"
	childNetmask = "255.255.255.0"
	gatewayIP    = "10.0.2.2"
)

// createTAP opens /dev/net/tun and configures a TAP device named "eth0".
// Returns the raw TAP file descriptor. The caller must close it when done.
func createTAP() (int, error) {
	fd, err := unix.Open(tapDevicePath, unix.O_RDWR, 0)
	if err != nil {
		return -1, fmt.Errorf("opening %s: %w", tapDevicePath, err)
	}

	ifr, err := unix.NewIfreq(tapName)
	if err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("creating ifreq: %w", err)
	}
	// IFF_TAP: layer-2 (Ethernet frames), IFF_NO_PI: no packet info header.
	ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("TUNSETIFF: %w", err)
	}

	return fd, nil
}

// configureInterfaces brings up lo and eth0, sets IP/netmask on eth0,
// and adds a default route via the gateway.
func configureInterfaces() error {
	// We need a socket for ioctl calls.
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket for ioctl: %w", err)
	}
	defer func() { _ = unix.Close(sock) }()

	// Bring up loopback.
	if err := setInterfaceUp(sock, "lo"); err != nil {
		return fmt.Errorf("bringing up lo: %w", err)
	}

	// Set eth0 IP address.
	if err := setInterfaceAddr(sock, tapName, childIP); err != nil {
		return fmt.Errorf("setting %s IP: %w", tapName, err)
	}

	// Set eth0 netmask.
	if err := setInterfaceNetmask(sock, tapName, childNetmask); err != nil {
		return fmt.Errorf("setting %s netmask: %w", tapName, err)
	}

	// Bring up eth0.
	if err := setInterfaceUp(sock, tapName); err != nil {
		return fmt.Errorf("bringing up %s: %w", tapName, err)
	}

	// Add default route via gateway.
	ifindex, err := getInterfaceIndex(sock, tapName)
	if err != nil {
		return fmt.Errorf("getting %s index: %w", tapName, err)
	}
	if err := addDefaultRoute(gatewayIP, ifindex); err != nil {
		return fmt.Errorf("adding default route: %w", err)
	}

	return nil
}

// setInterfaceUp brings a network interface up using ioctl SIOCSIFFLAGS.
func setInterfaceUp(sock int, name string) error {
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	// Get current flags.
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

// setInterfaceAddr sets the IPv4 address on an interface using ioctl SIOCSIFADDR.
func setInterfaceAddr(sock int, name, addr string) error {
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address: %s", addr)
	}
	if err := ifr.SetInet4Addr(ip); err != nil {
		return err
	}
	if err := unix.IoctlIfreq(sock, unix.SIOCSIFADDR, ifr); err != nil {
		return fmt.Errorf("SIOCSIFADDR: %w", err)
	}
	return nil
}

// setInterfaceNetmask sets the IPv4 netmask on an interface using ioctl SIOCSIFNETMASK.
func setInterfaceNetmask(sock int, name, mask string) error {
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	ip := net.ParseIP(mask).To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4 netmask: %s", mask)
	}
	if err := ifr.SetInet4Addr(ip); err != nil {
		return err
	}
	if err := unix.IoctlIfreq(sock, unix.SIOCSIFNETMASK, ifr); err != nil {
		return fmt.Errorf("SIOCSIFNETMASK: %w", err)
	}
	return nil
}

// getInterfaceIndex returns the ifindex for a named interface.
func getInterfaceIndex(sock int, name string) (int, error) {
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return 0, err
	}
	if err := unix.IoctlIfreq(sock, unix.SIOCGIFINDEX, ifr); err != nil {
		return 0, fmt.Errorf("SIOCGIFINDEX: %w", err)
	}
	return int(ifr.Uint32()), nil
}

// addDefaultRoute adds a default route (0.0.0.0/0) via the given gateway using netlink.
func addDefaultRoute(gw string, ifindex int) error {
	gwIP := net.ParseIP(gw).To4()
	if gwIP == nil {
		return fmt.Errorf("invalid gateway IP: %s", gw)
	}

	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer func() { _ = unix.Close(sock) }()

	if err := unix.Bind(sock, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}

	// Build RTM_NEWROUTE message.
	msg := unix.RtMsg{
		Family:   unix.AF_INET,
		Dst_len:  0, // default route
		Table:    unix.RT_TABLE_MAIN,
		Protocol: unix.RTPROT_BOOT,
		Scope:    unix.RT_SCOPE_UNIVERSE,
		Type:     unix.RTN_UNICAST,
	}

	const rtMsgSize = int(unsafe.Sizeof(unix.RtMsg{}))
	hdrLen := unix.NLMSG_HDRLEN + rtMsgSize

	// RTA_GATEWAY attribute.
	gwAttr := nlAttr(unix.RTA_GATEWAY, gwIP)
	// RTA_OIF attribute.
	oifBuf := make([]byte, 4)
	binary.NativeEndian.PutUint32(oifBuf, uint32(ifindex))
	oifAttr := nlAttr(unix.RTA_OIF, oifBuf)

	totalLen := hdrLen + len(gwAttr) + len(oifAttr)

	buf := make([]byte, totalLen)
	// NLMsgHdr.
	binary.NativeEndian.PutUint32(buf[0:4], uint32(totalLen))         // nlmsg_len
	binary.NativeEndian.PutUint16(buf[4:6], unix.RTM_NEWROUTE)        // nlmsg_type
	binary.NativeEndian.PutUint16(buf[6:8], unix.NLM_F_REQUEST|unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK) // nlmsg_flags
	binary.NativeEndian.PutUint32(buf[8:12], 1)                       // nlmsg_seq
	// RtMsg payload.
	rtBuf := buf[unix.NLMSG_HDRLEN:]
	rtBuf[0] = msg.Family
	rtBuf[1] = msg.Dst_len
	rtBuf[2] = msg.Src_len
	rtBuf[3] = msg.Tos
	rtBuf[4] = msg.Table
	rtBuf[5] = msg.Protocol
	rtBuf[6] = msg.Scope
	rtBuf[7] = msg.Type
	// Attributes.
	off := hdrLen
	copy(buf[off:], gwAttr)
	off += len(gwAttr)
	copy(buf[off:], oifAttr)

	if err := unix.Sendto(sock, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink send: %w", err)
	}

	// Read ack.
	ackBuf := make([]byte, 1024)
	n, _, err := unix.Recvfrom(sock, ackBuf, 0)
	if err != nil {
		return fmt.Errorf("netlink recv: %w", err)
	}
	if n >= unix.NLMSG_HDRLEN+4 {
		nlType := binary.NativeEndian.Uint16(ackBuf[4:6])
		if nlType == unix.NLMSG_ERROR {
			errno := int32(binary.NativeEndian.Uint32(ackBuf[unix.NLMSG_HDRLEN : unix.NLMSG_HDRLEN+4]))
			if errno != 0 {
				return fmt.Errorf("netlink error: %w", unix.Errno(-errno))
			}
		}
	}

	return nil
}

// nlAttr builds a netlink attribute (NLA header + payload, padded to 4 bytes).
func nlAttr(typ uint16, data []byte) []byte {
	attrLen := 4 + len(data) // NLA header is 4 bytes.
	padded := (attrLen + 3) &^ 3
	buf := make([]byte, padded)
	binary.NativeEndian.PutUint16(buf[0:2], uint16(attrLen))
	binary.NativeEndian.PutUint16(buf[2:4], typ)
	copy(buf[4:], data)
	return buf
}

