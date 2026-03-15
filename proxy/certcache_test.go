package proxy

import (
	"crypto/tls"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertCache_Hit(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)
	cc := NewCertCache(ca)

	hello := &tls.ClientHelloInfo{ServerName: "example.com"}
	cert1, err := cc.GetCertificate(hello)
	require.NoError(t, err)

	cert2, err := cc.GetCertificate(hello)
	require.NoError(t, err)

	// Same pointer means cache hit.
	assert.Same(t, cert1, cert2)
}

func TestCertCache_DifferentHosts(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)
	cc := NewCertCache(ca)

	cert1, err := cc.GetCertificate(&tls.ClientHelloInfo{ServerName: "foo.com"})
	require.NoError(t, err)

	cert2, err := cc.GetCertificate(&tls.ClientHelloInfo{ServerName: "bar.com"})
	require.NoError(t, err)

	assert.NotSame(t, cert1, cert2)
}

func TestCertCache_NoSNI(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)
	cc := NewCertCache(ca)

	_, err = cc.GetCertificate(&tls.ClientHelloInfo{})
	assert.Error(t, err)
}

func TestCertCache_SizeLimit(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)
	cc := NewCertCache(ca)

	// Fill the cache to the limit.
	for i := range maxCachedCerts {
		_, err := cc.certFor(fmt.Sprintf("host-%d.example.com", i))
		require.NoError(t, err)
	}
	assert.Equal(t, int64(maxCachedCerts), cc.size.Load())

	// One more should fail.
	_, err = cc.certFor("overflow.example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cache full")

	// Existing entries should still be served.
	_, err = cc.certFor("host-0.example.com")
	assert.NoError(t, err)
}

func TestCertCache_Concurrent(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)
	cc := NewCertCache(ca)

	var wg sync.WaitGroup
	results := make([]*tls.Certificate, 100)
	for i := range 100 {
		wg.Go(func() {
			cert, cerr := cc.GetCertificate(&tls.ClientHelloInfo{ServerName: "concurrent.com"})
			if cerr == nil {
				results[i] = cert
			}
		})
	}
	wg.Wait()

	// All should return the same pointer (only one cert generated).
	first := results[0]
	require.NotNil(t, first)
	for _, r := range results[1:] {
		assert.Same(t, first, r)
	}
}
