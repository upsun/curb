package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// CA is an ephemeral certificate authority for MITM proxy TLS termination.
// It is generated per curb invocation and only trusted inside the sandbox.
type CA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
}

// NewCA generates an ephemeral ECDSA P-256 CA certificate.
// The CA is self-signed with a 10-year validity (the real lifetime is bounded
// by the curb process, not the cert).
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "curb ephemeral CA",
			Organization: []string{"curb"},
		},
		NotBefore:             now.Add(-5 * time.Minute), // Clock skew tolerance.
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return &CA{Cert: cert, Key: key, CertPEM: certPEM}, nil
}

// IssueCert generates a TLS certificate for the given hostname, signed by the CA.
// The hostname is added as a SAN (DNS name or IP address).
func (ca *CA) IssueCert(hostname string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating cert key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore: ca.Cert.NotBefore,
		NotAfter:  ca.Cert.NotAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("creating certificate for %s: %w", hostname, err)
	}

	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parsing certificate for %s: %w", hostname, err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// randomSerial generates a random 128-bit serial number for certificates.
func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}
	return serial, nil
}
