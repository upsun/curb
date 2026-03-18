//go:build !linux && !darwin

package proxy

// systemCACertPaths is empty on unsupported platforms.
var systemCACertPaths []string
