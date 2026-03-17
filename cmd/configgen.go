package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

// NewConfigGenCmd creates the "config-gen" subcommand.
func NewConfigGenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config-gen",
		Short: "Generate a .curb.yaml config file",
		Long: `Generate a .curb.yaml config file.

Without --from-log: writes a commented YAML template to stdout.
With --from-log: reads a JSON log file and extracts allowed domains and IPs.

To discover needed domains, run with --domains '*' --log-file FILE, then:
  curb config-gen --from-log FILE`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			logFile, _ := cmd.Flags().GetString("from-log")
			if logFile == "" {
				printTemplate()
				return nil
			}
			return genFromLog(logFile)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().String("from-log", "", "JSON log file to extract domains/IPs from")
	return cmd
}

func printTemplate() {
	fmt.Print(`# .curb.yaml — curb sandbox configuration.
# See: https://github.com/upsun/curb

# Activate named profiles (built-in: node, python, php, go, rust, git, github, docker, claude-code).
# profiles:
#   - node
#   - git

# Allowed network domains (supports wildcards like *.example.com).
# domains:
#   - example.com
#   - "*.example.com"

# Allowed IP addresses or CIDR ranges.
# ips:
#   - 10.0.0.0/8

# Readable paths (added to defaults; use ! prefix to deny).
# read:
#   - ~/.cache

# Writable paths (use ! prefix to make read-only).
# write:
#   - .

# Allowed executables (use ! prefix to remove defaults).
# exec:
#   - python3

# Environment variables to pass through or set (NAME or NAME=value).
# env:
#   - VIRTUAL_ENV

# Set HOME for the sandboxed process.
# home: "~"

# MITM proxy mode: on, off.
# proxy: "on"

# TUN/TAP netstack: auto, always.
# tun: auto

# ECH handling: strip, allow, deny.
# ech: strip

# Allow plaintext HTTP when domain filtering is active.
# allow-http: false

# Allow TLS connections without SNI.
# allow-no-sni: false

# Skip network namespace entirely.
# unrestricted-net: false
`)
}

// logEntry represents the fields we care about from a JSON log line.
type logEntry struct {
	Msg    string `json:"msg"`
	Event  string `json:"event"`
	Domain string `json:"domain"`
	Action string `json:"action"`
}

func genFromLog(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening log file: %w", err)
	}
	defer func() { _ = f.Close() }()

	domains := make(map[string]bool)
	ips := make(map[string]bool)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry logEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if entry.Action != "allowed" || entry.Domain == "" {
			continue
		}
		host := entry.Domain
		// Strip port if present.
		if h, _, ok := strings.Cut(host, ":"); ok {
			host = h
		}
		if host == "" {
			continue
		}
		if _, err := netip.ParseAddr(host); err == nil {
			ips[host] = true
		} else {
			domains[host] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading log file: %w", err)
	}

	fmt.Println("# .curb.yaml — generated from log file.")
	fmt.Println("# Review and adjust before use.")
	fmt.Println("# FS and exec paths cannot be extracted from logs (kernel denials are invisible).")

	if len(domains) > 0 {
		sortedDomains := sortedKeys(domains)
		fmt.Println("domains:")
		for _, d := range sortedDomains {
			fmt.Printf("  - %s\n", d)
		}
	}
	if len(ips) > 0 {
		fmt.Println("# Some IPs may be resolved addresses of listed domains.")
		sortedIPs := sortedKeys(ips)
		fmt.Println("ips:")
		for _, ip := range sortedIPs {
			fmt.Printf("  - %s\n", ip)
		}
	}

	return nil
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
