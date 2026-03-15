//go:build linux

package sandbox

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
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
// and adds a default route via the gateway. Returns the ifindex for eth0.
func configureInterfaces() (int, error) {
	// We need a socket for ioctl calls.
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return 0, fmt.Errorf("socket for ioctl: %w", err)
	}
	defer func() { _ = unix.Close(sock) }()

	// Bring up loopback.
	if err := setInterfaceUp(sock, "lo"); err != nil {
		return 0, fmt.Errorf("bringing up lo: %w", err)
	}

	// Set eth0 IP address and netmask.
	if err := setInterfaceInet4(sock, tapName, childIP, unix.SIOCSIFADDR); err != nil {
		return 0, fmt.Errorf("setting %s IP: %w", tapName, err)
	}
	if err := setInterfaceInet4(sock, tapName, childNetmask, unix.SIOCSIFNETMASK); err != nil {
		return 0, fmt.Errorf("setting %s netmask: %w", tapName, err)
	}

	// Bring up eth0.
	if err := setInterfaceUp(sock, tapName); err != nil {
		return 0, fmt.Errorf("bringing up %s: %w", tapName, err)
	}

	// Add default route via gateway.
	ifindex, err := getInterfaceIndex(sock, tapName)
	if err != nil {
		return 0, fmt.Errorf("getting %s index: %w", tapName, err)
	}
	if err := addRoute(nil, gatewayIP, ifindex); err != nil {
		return 0, fmt.Errorf("adding default route: %w", err)
	}

	return ifindex, nil
}

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

// setInterfaceInet4 sets an IPv4 sockaddr field on an interface via ioctl.
// Used for both SIOCSIFADDR and SIOCSIFNETMASK.
func setInterfaceInet4(sock int, name, addr string, ioctlCmd uint) error {
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4: %s", addr)
	}
	if err := ifr.SetInet4Addr(ip); err != nil {
		return err
	}
	if err := unix.IoctlIfreq(sock, ioctlCmd, ifr); err != nil {
		return fmt.Errorf("ioctl %#x: %w", ioctlCmd, err)
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

// addRoute adds a route via the given gateway using netlink.
// If dst is nil, adds a default route (0.0.0.0/0). Otherwise adds a /32 host route.
func addRoute(dst net.IP, gw string, ifindex int) error {
	var prefixLen uint8
	if dst != nil {
		prefixLen = 32
	}
	return addRoutePrefix(dst, prefixLen, gw, ifindex)
}

// addSubnetRoute adds a route for a CIDR prefix via the given gateway.
func addSubnetRoute(dst net.IP, prefixLen uint8, gw string, ifindex int) error {
	return addRoutePrefix(dst, prefixLen, gw, ifindex)
}

// addRoutePrefix adds a route with the given prefix length via the gateway using netlink.
func addRoutePrefix(dst net.IP, dstLen uint8, gw string, ifindex int) error {
	gwIP := net.ParseIP(gw).To4()
	if gwIP == nil {
		return fmt.Errorf("invalid gateway IP: %s", gw)
	}

	sock, err := nlRouteSocket()
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(sock) }()

	const rtMsgSize = int(unsafe.Sizeof(unix.RtMsg{}))
	hdrLen := unix.NLMSG_HDRLEN + rtMsgSize

	// Build attributes.
	var attrs []byte
	if dst != nil {
		attrs = append(attrs, nlAttr(unix.RTA_DST, dst.To4())...)
	}
	attrs = append(attrs, nlAttr(unix.RTA_GATEWAY, gwIP)...)
	oifBuf := make([]byte, 4)
	binary.NativeEndian.PutUint32(oifBuf, uint32(ifindex))
	attrs = append(attrs, nlAttr(unix.RTA_OIF, oifBuf)...)

	totalLen := hdrLen + len(attrs)
	buf := make([]byte, totalLen)

	// Netlink message header.
	binary.NativeEndian.PutUint32(buf[0:4], uint32(totalLen))
	binary.NativeEndian.PutUint16(buf[4:6], unix.RTM_NEWROUTE)
	binary.NativeEndian.PutUint16(buf[6:8], unix.NLM_F_REQUEST|unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(buf[8:12], 1) // seq

	// RtMsg payload.
	rtBuf := buf[unix.NLMSG_HDRLEN:]
	rtBuf[0] = unix.AF_INET // Family
	rtBuf[1] = dstLen       // Dst_len
	rtBuf[4] = unix.RT_TABLE_MAIN
	rtBuf[5] = unix.RTPROT_BOOT
	rtBuf[6] = unix.RT_SCOPE_UNIVERSE
	rtBuf[7] = unix.RTN_UNICAST
	copy(buf[hdrLen:], attrs)

	return nlRouteSend(sock, buf)
}

// routeLoopback redirects loopback traffic (127.0.0.0/8) through the TAP
// device so it reaches the parent's netstack instead of staying on lo.
// This is needed for DNS (e.g. 127.0.0.53 systemd-resolved) and for
// --domains localhost forwarding of 127.0.0.1 connections.
func routeLoopback(ifindex int) error {
	// Delete the kernel's local-table routes for 127.0.0.0/8. These are
	// auto-created when lo is brought up and have higher priority than the
	// main table (local table is checked at priority 0, main at 32766).
	// Without removing them, loopback traffic is delivered to lo (where
	// nothing listens) instead of being routed through the TAP.
	if err := deleteLocalLoopbackRoutes(); err != nil {
		return fmt.Errorf("deleting local loopback routes: %w", err)
	}

	// Enable route_localnet so 127.0.0.0/8 can be routed through non-loopback interfaces.
	// Safe: this is an isolated network namespace with nothing on its loopback.
	sysctl := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/route_localnet", tapName)
	if err := os.WriteFile(sysctl, []byte("1"), 0o644); err != nil {
		return fmt.Errorf("writing route_localnet: %w", err)
	}

	// Route all of 127.0.0.0/8 through the TAP. This covers both DNS
	// nameservers (e.g. 127.0.0.53) and localhost services (127.0.0.1).
	if err := addSubnetRoute(net.IPv4(127, 0, 0, 0), 8, gatewayIP, ifindex); err != nil {
		return fmt.Errorf("adding loopback route: %w", err)
	}
	return nil
}

// deleteLocalLoopbackRoutes removes the kernel's auto-created local-table
// routes for 127.0.0.0/8 (added when lo is brought up). These are:
//   - local 127.0.0.0/8 dev lo (scope host)
//   - local 127.0.0.1/32 dev lo (scope host)
//   - broadcast 127.255.255.255/32 dev lo (scope link)
func deleteLocalLoopbackRoutes() error {
	sock, err := nlRouteSocket()
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(sock) }()

	routes := []struct {
		dst   net.IP
		pfx   uint8
		typ   uint8
		scope uint8
	}{
		{net.IPv4(127, 0, 0, 0), 8, unix.RTN_LOCAL, unix.RT_SCOPE_HOST},
		{net.IPv4(127, 0, 0, 1), 32, unix.RTN_LOCAL, unix.RT_SCOPE_HOST},
		{net.IPv4(127, 255, 255, 255), 32, unix.RTN_BROADCAST, unix.RT_SCOPE_LINK},
	}

	const rtMsgSize = int(unsafe.Sizeof(unix.RtMsg{}))
	hdrLen := unix.NLMSG_HDRLEN + rtMsgSize

	for _, r := range routes {
		attrs := nlAttr(unix.RTA_DST, r.dst.To4())
		totalLen := hdrLen + len(attrs)
		buf := make([]byte, totalLen)

		binary.NativeEndian.PutUint32(buf[0:4], uint32(totalLen))
		binary.NativeEndian.PutUint16(buf[4:6], unix.RTM_DELROUTE)
		binary.NativeEndian.PutUint16(buf[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
		binary.NativeEndian.PutUint32(buf[8:12], 1) // seq

		rtBuf := buf[unix.NLMSG_HDRLEN:]
		rtBuf[0] = unix.AF_INET        // Family
		rtBuf[1] = r.pfx               // Dst_len
		rtBuf[4] = unix.RT_TABLE_LOCAL // Table
		rtBuf[5] = unix.RTPROT_KERNEL  // Protocol
		rtBuf[6] = r.scope             // Scope
		rtBuf[7] = r.typ               // Type
		copy(buf[hdrLen:], attrs)

		if err := nlRouteSend(sock, buf); err != nil {
			return err
		}
	}
	return nil
}

// nlRouteSocket creates and binds a netlink route socket.
func nlRouteSocket() (int, error) {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, fmt.Errorf("netlink socket: %w", err)
	}
	if err := unix.Bind(sock, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(sock)
		return -1, fmt.Errorf("netlink bind: %w", err)
	}
	return sock, nil
}

// nlRouteSend sends a pre-built netlink message and waits for the ack.
func nlRouteSend(sock int, msg []byte) error {
	if err := unix.Sendto(sock, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink send: %w", err)
	}
	ackBuf := make([]byte, 128)
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
