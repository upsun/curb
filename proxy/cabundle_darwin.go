//go:build darwin

package proxy

// systemCACertPaths lists the system CA bundle file path on macOS.
var systemCACertPaths = []string{
	"/etc/ssl/cert.pem",
}
