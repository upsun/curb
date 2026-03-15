package proxy

import (
	"crypto/tls"
	"fmt"
	"sync"
	"sync/atomic"
)

// maxCachedCerts limits the number of cached certificates to bound memory and
// CPU usage. A sandboxed process connecting to many unique hostnames will get
// errors once the limit is reached.
const maxCachedCerts = 1000

// CertCache is a thread-safe cache of TLS certificates keyed by hostname.
// It generates certificates on demand using the provided CA.
type CertCache struct {
	ca    *CA
	cache sync.Map // map[string]*tls.Certificate
	size  atomic.Int64
}

// NewCertCache creates a new CertCache backed by the given CA.
func NewCertCache(ca *CA) *CertCache {
	return &CertCache{ca: ca}
}

// GetCertificate returns a cached or newly issued TLS certificate for the
// hostname in the ClientHello. It implements the tls.Config.GetCertificate
// callback signature.
func (cc *CertCache) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := hello.ServerName
	if name == "" {
		return nil, fmt.Errorf("no SNI in ClientHello")
	}
	return cc.certFor(name)
}

// certFor returns a cached or newly issued certificate for the given hostname.
func (cc *CertCache) certFor(hostname string) (*tls.Certificate, error) {
	if val, ok := cc.cache.Load(hostname); ok {
		return val.(*tls.Certificate), nil
	}
	// Reserve a slot atomically before doing expensive key generation.
	// Compensate if the reservation is not used (cache full, error, or
	// another goroutine won the race for the same hostname).
	if cc.size.Add(1) > maxCachedCerts {
		cc.size.Add(-1)
		return nil, fmt.Errorf("certificate cache full (%d entries)", maxCachedCerts)
	}
	cert, err := cc.ca.IssueCert(hostname)
	if err != nil {
		cc.size.Add(-1)
		return nil, err
	}
	actual, loaded := cc.cache.LoadOrStore(hostname, &cert)
	if loaded {
		cc.size.Add(-1) // Another goroutine stored this hostname first.
	}
	return actual.(*tls.Certificate), nil
}
