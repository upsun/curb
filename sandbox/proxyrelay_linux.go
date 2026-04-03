//go:build linux

package sandbox

import (
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/upsun/curb/clog"
)

// proxyRelayInit runs in the child process for proxy mode.
// It brings up loopback, starts TCP listeners for the HTTP and SOCKS5 proxies,
// and relays accepted connection fds to the parent via the socketpair. The
// target command is fork+exec'd (the Go runtime must stay alive for the accept
// loops).
func proxyRelayInit(sockFile *os.File, cfg *ChildConfig, log *clog.Logger) error {
	if err := bringUpLoopback(); err != nil {
		return err
	}

	httpAddr := fmt.Sprintf("127.0.0.1:%d", cfg.ProxyPort)
	httpLn, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", httpAddr, err)
	}
	listeners := []net.Listener{httpLn}
	closeAll := func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}

	var socksLn net.Listener
	if cfg.SOCKSPort > 0 {
		socksAddr := fmt.Sprintf("127.0.0.1:%d", cfg.SOCKSPort)
		socksLn, err = net.Listen("tcp", socksAddr)
		if err != nil {
			closeAll()
			return fmt.Errorf("listening on %s: %w", socksAddr, err)
		}
		listeners = append(listeners, socksLn)
	}

	if err := enforceFS(cfg, log); err != nil {
		closeAll()
		return err
	}

	// Seccomp: block AF_UNIX socket creation. Applied after FS enforcement
	// but before fork+exec so the user command inherits the filter.
	// The accept loops use TCP (AF_INET) and existing fds, so are unaffected.
	if err := enforceSeccomp(cfg.AllowUnixSockets, log); err != nil {
		closeAll()
		return err
	}

	if len(cfg.Command) == 0 {
		closeAll()
		return fmt.Errorf("no command specified")
	}
	exe, err := findExecutable(cfg.Command[0], cfg.Env)
	if err != nil {
		closeAll()
		return err
	}

	// Mutex protects the socketpair from concurrent sendmsg calls.
	// Without this, tag bytes and fds from the two accept loops can
	// interleave on the SOCK_STREAM socket, causing misdispatch.
	var sendMu sync.Mutex

	go relayAcceptLoop(httpLn, sockFile, FDTagHTTP, &sendMu)
	if socksLn != nil {
		go relayAcceptLoop(socksLn, sockFile, FDTagSOCKS5, &sendMu)
	}

	return initLoop(exe, cfg.Command, cfg.Env, func() {
		closeAll()
		_ = sockFile.Close()
	})
}

// relayAcceptLoop accepts TCP connections on ln and sends their fds to the
// parent via sockFile, tagged with the given fd tag byte.
func relayAcceptLoop(ln net.Listener, sockFile *os.File, tag byte, sendMu *sync.Mutex) {
	defer func() { _ = ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
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
		sendMu.Lock()
		sendErr := SendFD(sockFile, int(f.Fd()), tag)
		sendMu.Unlock()
		if sendErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "curb: proxy relay: send fd: %v\n", sendErr)
		}
		_ = f.Close()
		_ = tcpConn.Close()
	}
}
