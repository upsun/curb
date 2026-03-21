//go:build linux

package sandbox

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// TestCurb_Proxy_SOCKS5SSH tests SSH via the SOCKS5 proxy using the built-in
// _socks-connect helper as ProxyCommand. A lightweight Go SSH server runs in
// the test process; the sandboxed ssh client connects through SOCKS5.
func TestCurb_Proxy_SOCKS5SSH(t *testing.T) {
	requireProxyNS(t)

	// Generate an ephemeral host key.
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(hostKey)
	require.NoError(t, err)

	// SSH server config: no client auth (for testing).
	sshCfg := &ssh.ServerConfig{NoClientAuth: true}
	sshCfg.AddHostKey(signer)

	// Listen on a random port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	_, sshPort, _ := net.SplitHostPort(ln.Addr().String())

	// Accept one connection and handle it.
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		srvConn, chans, reqs, srvErr := ssh.NewServerConn(conn, sshCfg)
		if srvErr != nil {
			return
		}
		defer func() { _ = srvConn.Close() }()
		go ssh.DiscardRequests(reqs)

		for newChan := range chans {
			if newChan.ChannelType() != "session" {
				_ = newChan.Reject(ssh.UnknownChannelType, "unsupported")
				continue
			}
			ch, requests, chErr := newChan.Accept()
			if chErr != nil {
				continue
			}
			go func() {
				defer func() { _ = ch.Close() }()
				for req := range requests {
					if req.Type == "exec" {
						// Write a marker so the test can verify the connection worked.
						_, _ = ch.Write([]byte("SOCKS5-SSH-OK\n"))
						_ = ch.CloseWrite()
						_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						if req.WantReply {
							_ = req.Reply(true, nil)
						}
						return
					}
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}()
		}
	}()

	// Run curb with ssh connecting through SOCKS5.
	// The curb binary path must be passed explicitly for ProxyCommand since
	// the sandbox child's $0 is "sh", not curb.
	cmd := exec.Command(curbBin, "--write", "*", "--exec", "*",
		"--read", "*",
		"--domains", "localhost",
		"--", "sh", "-c",
		fmt.Sprintf(
			"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "+
				"-o \"ProxyCommand=%s _socks-connect %%h %%p\" "+
				"-p %s testuser@localhost echo hello",
			curbBin, sshPort,
		),
	)
	out, err := cmd.CombinedOutput()
	outStr := filterCurbOutput(string(out))
	require.NoError(t, err, "ssh via SOCKS5 failed: %s", outStr)
	assert.Contains(t, outStr, "SOCKS5-SSH-OK")
}
