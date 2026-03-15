package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCA(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	assert.True(t, ca.Cert.IsCA)
	assert.True(t, ca.Cert.BasicConstraintsValid)
	assert.Equal(t, "curb ephemeral CA", ca.Cert.Subject.CommonName)
	assert.NotEmpty(t, ca.CertPEM)

	// CA cert should be self-signed.
	err = ca.Cert.CheckSignatureFrom(ca.Cert)
	assert.NoError(t, err)
}

func TestIssueCert_Domain(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	cert, err := ca.IssueCert("example.com")
	require.NoError(t, err)

	// Parse the leaf.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	assert.Contains(t, leaf.DNSNames, "example.com")
	assert.Empty(t, leaf.IPAddresses)

	// Verify chain.
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	assert.NoError(t, err)
}

func TestIssueCert_IP(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	cert, err := ca.IssueCert("10.0.0.1")
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	assert.Empty(t, leaf.DNSNames)
	assert.Contains(t, leaf.IPAddresses, net.ParseIP("10.0.0.1").To4())
}

func TestIssueCert_DistinctCerts(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	cert1, err := ca.IssueCert("foo.com")
	require.NoError(t, err)
	cert2, err := ca.IssueCert("bar.com")
	require.NoError(t, err)

	leaf1, _ := x509.ParseCertificate(cert1.Certificate[0])
	leaf2, _ := x509.ParseCertificate(cert2.Certificate[0])

	assert.NotEqual(t, leaf1.SerialNumber, leaf2.SerialNumber)
	assert.NotEqual(t, leaf1.DNSNames, leaf2.DNSNames)
}

func TestIssueCert_UsableForTLS(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	cert, err := ca.IssueCert("localhost")
	require.NoError(t, err)

	// Verify it can be used in a tls.Config.
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	assert.Len(t, tlsCfg.Certificates, 1)
}
