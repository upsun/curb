package cmd

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/spf13/cobra"
	"github.com/upsun/curb/sandbox"
	"golang.org/x/net/proxy"
)

// NewSocksConnectCmd creates the hidden _socks-connect subcommand.
// It is used as an SSH ProxyCommand to route connections through the
// curb SOCKS5 proxy without requiring external tools like nc.
func NewSocksConnectCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "_socks-connect HOST PORT",
		Short:  "SOCKS5 proxy connector for SSH ProxyCommand",
		Hidden: true,
		Args:   cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			return runSocksConnect(args[0], args[1])
		},
	}
}

func runSocksConnect(host, port string) error {
	proxyAddr := os.Getenv(sandbox.SOCKSAddrEnvKey)
	if proxyAddr == "" {
		return fmt.Errorf("%s not set", sandbox.SOCKSAddrEnvKey)
	}

	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return fmt.Errorf("creating SOCKS5 dialer: %w", err)
	}

	conn, err := dialer.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return fmt.Errorf("socks5 connect to %s:%s: %w", host, port, err)
	}
	defer func() { _ = conn.Close() }()

	// Relay stdin/stdout <-> SOCKS5 connection.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, os.Stdin)
		if tc, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(os.Stdout, conn)
	}()
	wg.Wait()
	return nil
}
