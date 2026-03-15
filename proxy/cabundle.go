package proxy

import (
	"fmt"
	"os"
	"path/filepath"
)

// systemCACertPaths lists well-known system CA bundle file paths.
// Matches Go stdlib crypto/x509.certFiles (root_linux.go).
var systemCACertPaths = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo
	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
	"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
	"/etc/pki/tls/cacert.pem",                           // OpenELEC
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
	"/etc/ssl/cert.pem",                                 // Alpine Linux
}

// SystemCACertPath returns the first existing system CA bundle path, or ""
// if none is found.
func SystemCACertPath() string {
	for _, p := range systemCACertPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// WriteCombinedBundle writes a combined CA bundle (system certs + ephemeral CA)
// into dir. It returns the path to the combined bundle and the system CA path
// that was used (for bind-mount overmounting).
func WriteCombinedBundle(dir string, ca *CA) (bundlePath, systemPath string, err error) {
	systemPath = SystemCACertPath()
	if systemPath == "" {
		return "", "", fmt.Errorf("no system CA bundle found")
	}

	systemBundle, err := os.ReadFile(systemPath)
	if err != nil {
		return "", "", fmt.Errorf("reading system CA bundle: %w", err)
	}

	// Append ephemeral CA PEM to system bundle.
	combined := make([]byte, 0, len(systemBundle)+1+len(ca.CertPEM))
	combined = append(combined, systemBundle...)
	if len(combined) > 0 && combined[len(combined)-1] != '\n' {
		combined = append(combined, '\n')
	}
	combined = append(combined, ca.CertPEM...)

	bundlePath = filepath.Join(dir, "ca-certificates.crt")
	if err := os.WriteFile(bundlePath, combined, 0o644); err != nil {
		return "", "", fmt.Errorf("writing combined CA bundle: %w", err)
	}

	return bundlePath, systemPath, nil
}
