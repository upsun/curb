//go:build linux

package sandbox

import (
	"fmt"
	"net"
	"os"
)

// proxyRelayInit runs in the child process for proxy-only mode (no TUN/TAP).
// It brings up loopback, starts a TCP listener, and relays accepted connection
// fds to the parent via the socketpair. The target command is fork+exec'd
// (the Go runtime must stay alive for the accept loop).
func proxyRelayInit(sockFile *os.File, cfg *ChildConfig) error {
	// Bring up lo (only network in the empty net NS).
	if err := bringUpLoopback(); err != nil {
		return err
	}

	// Listen on the proxy port.
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.ProxyPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}

	// Apply FS enforcement before fork+exec.
	if err := enforceFS(cfg); err != nil {
		_ = ln.Close()
		return err
	}

	if len(cfg.Command) == 0 {
		_ = ln.Close()
		return fmt.Errorf("no command specified")
	}
	exe, err := findExecutable(cfg.Command[0], cfg.Env)
	if err != nil {
		_ = ln.Close()
		return err
	}

	// Start accept loop in a goroutine: accept TCP connections and send
	// their fds to the parent via the socketpair.
	go func() {
		defer func() { _ = ln.Close() }()
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return // Listener closed.
			}
			tcpConn, ok := conn.(*net.TCPConn)
			if !ok {
				_ = conn.Close()
				continue
			}
			f, fileErr := tcpConn.File()
			if fileErr != nil {
				_ = tcpConn.Close()
				continue
			}
			// Send the fd to the parent.
			if sendErr := SendFD(sockFile, int(f.Fd())); sendErr != nil {
				_, _ = fmt.Fprintf(os.Stderr, "curb: proxy relay: send fd: %v\n", sendErr)
			}
			_ = f.Close()
			_ = tcpConn.Close()
		}
	}()

	// Fork+exec the target. initLoop handles signal forwarding and reap.
	return initLoop(exe, cfg.Command, cfg.Env, func() {
		_ = ln.Close()
		_ = sockFile.Close()
	})
}
