// Package netstack provides userspace TCP/IP networking via gvisor netstack.
package netstack

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	nicID = 1
	mtu   = 1500
)

// Stack wraps a gvisor network stack with TCP/UDP forwarding.
type Stack struct {
	s *stack.Stack
}

// NewStack creates a gvisor netstack backed by a TAP file descriptor.
// The stack responds to ARP and forwards TCP/UDP traffic to the real network.
// If dnsFilter is non-nil, UDP port 53 traffic is routed through it.
// The caller must not close tapFD after calling this; the stack owns it.
func NewStack(tapFD int, dnsFilter *DNSFilter) (*Stack, error) {
	// Static MAC for the gateway side of the TAP link.
	gwMAC := tcpip.LinkAddress([]byte{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02})

	ep, err := fdbased.New(&fdbased.Options{
		FDs:            []int{tapFD},
		MTU:            mtu,
		EthernetHeader: true,
		Address:        gwMAC,
	})
	if err != nil {
		return nil, fmt.Errorf("fdbased endpoint: %w", err)
	}

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			// Allow loopback-destined traffic (e.g. 127.0.0.53 for systemd-resolved)
			// to arrive via the TAP device. The child namespace uses route_localnet
			// to send such traffic through the TAP instead of its own loopback.
			ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: true}),
			arp.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	if err := s.CreateNIC(nicID, ep); err != nil {
		s.Close()
		return nil, fmt.Errorf("creating NIC: %s", err)
	}

	addr := tcpip.AddrFromSlice([]byte{10, 0, 2, 2})
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr, PrefixLen: 24},
	}
	if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		s.Close()
		return nil, fmt.Errorf("adding address: %s", err)
	}

	// Promiscuous mode and spoofing allow the stack to handle traffic
	// for arbitrary destinations (needed for forwarding).
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		s.Close()
		return nil, fmt.Errorf("setting promiscuous mode: %s", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		s.Close()
		return nil, fmt.Errorf("setting spoofing: %s", err)
	}

	// Default route: all traffic goes through our NIC.
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
	})

	// Set up TCP and UDP forwarding.
	setupTCPForwarding(s, dnsFilter)
	setupUDPForwarding(s, dnsFilter)

	return &Stack{s: s}, nil
}

// Close shuts down the network stack.
func (ns *Stack) Close() {
	ns.s.Close()
}
