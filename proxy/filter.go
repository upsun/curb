package proxy

import (
	"net"
	"net/netip"

	"github.com/upsun/curb/clog"
)

// FilterBase holds shared filtering, dialing, and logging fields used by
// both the HTTP MITM proxy (Handler) and the SOCKS5 proxy (SOCKS5Server).
type FilterBase struct {
	DomainCheck func(string) bool
	IPCheck     func(netip.Addr) bool
	Logger      *clog.Logger
	Dialer      *net.Dialer
}

// CheckTarget checks whether a target hostname or IP is allowed.
func (f *FilterBase) CheckTarget(host string) bool {
	if addr, err := netip.ParseAddr(host); err == nil {
		if f.IPCheck != nil {
			return f.IPCheck(addr)
		}
		return false
	}
	if f.DomainCheck != nil {
		return f.DomainCheck(host)
	}
	return false
}

func (f *FilterBase) getDialer() *net.Dialer {
	if f.Dialer != nil {
		return f.Dialer
	}
	return &net.Dialer{Timeout: dialTimeout}
}

func (f *FilterBase) logEvent(event, target, action, reason string) {
	if f.Logger == nil {
		return
	}
	f.Logger.Event(event, target, action, reason)
}
