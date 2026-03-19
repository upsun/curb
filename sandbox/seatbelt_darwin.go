//go:build darwin

package sandbox

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/upsun/curb/clog"
)

// generateSBPL converts a SandboxPlan into an SBPL (Seatbelt Profile Language)
// profile string for use with sandbox-exec -p.
func generateSBPL(plan *SandboxPlan) string {
	var b strings.Builder

	b.WriteString("(version 1)\n")
	b.WriteString("(deny default)\n")
	// system.sb imports dyld-support.sb which is required on modern macOS for
	// any process to start: it provides the rules dyld needs to bootstrap
	// (reading "/", mapping the dyld shared cache cryptex, special syscalls
	// for code-signing, etc.). Without this import every sandboxed process
	// aborts immediately with SIGABRT (exit 134) because dyld cannot
	// initialize the shared library runtime.
	b.WriteString("(import \"system.sb\")\n\n")

	writeProcessRules(&b, plan)
	writePTYRules(&b)
	writeSysctlRules(&b)
	writeMachRules(&b, plan)
	writeReadRules(&b, plan)
	writeWriteRules(&b, plan)
	writeExecRules(&b, plan)
	writeDenyRules(&b, plan)
	writeNetworkRules(&b, plan)

	return b.String()
}

// writeProcessRules emits process-fork, signal, and process-info rules.
func writeProcessRules(b *strings.Builder, plan *SandboxPlan) {
	b.WriteString(";; Process.\n")
	b.WriteString("(allow process-fork)\n")
	b.WriteString("(allow process-info* (target same-sandbox))\n")
	b.WriteString("(allow signal (target same-sandbox))\n")

	// process-exec is written separately in writeExecRules.
	b.WriteByte('\n')
}

// writePTYRules enables pseudo-tty operations for interactive terminals.
func writePTYRules(b *strings.Builder) {
	b.WriteString(";; PTY.\n")
	b.WriteString("(allow pseudo-tty)\n")
	b.WriteString("(allow file-read* file-write* file-ioctl\n")
	b.WriteString("  (literal \"/dev/ptmx\")\n")
	b.WriteString("  (regex #\"/dev/ttys[0-9]+$\"))\n\n")
}

// writeSysctlRules allows read-only sysctl access needed by common toolchains.
func writeSysctlRules(b *strings.Builder) {
	b.WriteString(";; Sysctl.\n")
	b.WriteString("(allow sysctl-read)\n\n")
}

// machServicesBase are mach services needed for basic process operation.
var machServicesBase = []string{
	"com.apple.bsd.dirhelper",
	"com.apple.logd",
	"com.apple.system.logger",
	"com.apple.system.notification_center",
	"com.apple.system.opendirectoryd.libinfo",
}

// machServicesNetwork are additional mach services needed for network/TLS.
var machServicesNetwork = []string{
	"com.apple.SecurityServer",
	"com.apple.ocspd",
	"com.apple.trustd.agent",
}

// machServicesDNS are mach services needed for DNS resolution.
var machServicesDNS = []string{
	"com.apple.mDNSResponder",
}

// writeMachRules emits mach-lookup rules. The set of allowed services depends
// on whether network access is enabled.
func writeMachRules(b *strings.Builder, plan *SandboxPlan) {
	b.WriteString(";; Mach IPC.\n")

	services := append([]string{}, machServicesBase...)
	if plan.ProxyEnabled || plan.UnrestrictedNet || len(plan.AllowedIPs) > 0 {
		services = append(services, machServicesNetwork...)
		services = append(services, machServicesDNS...)
	}

	b.WriteString("(allow mach-lookup\n")
	for _, s := range services {
		fmt.Fprintf(b, "  (global-name %q)\n", s)
	}
	b.WriteString(")\n\n")
}

// writeReadRules emits file-read* rules for read-only paths and files.
// When NoFSRestrict is set (--write *), all file access is allowed globally.
func writeReadRules(b *strings.Builder, plan *SandboxPlan) {
	if plan.NoFSRestrict {
		b.WriteString(";; FS (unrestricted).\n")
		b.WriteString("(allow file-read* file-write*)\n\n")
		return
	}
	if len(plan.ROPaths) == 0 && len(plan.ROFiles) == 0 {
		return
	}
	b.WriteString(";; Read-only paths.\n")
	if len(plan.ROPaths) > 0 {
		b.WriteString("(allow file-read*\n")
		for _, p := range plan.ROPaths {
			fmt.Fprintf(b, "  (subpath %q)\n", p)
		}
		b.WriteString(")\n")
	}
	if len(plan.ROFiles) > 0 {
		b.WriteString("(allow file-read*\n")
		for _, f := range plan.ROFiles {
			fmt.Fprintf(b, "  (literal %q)\n", f)
		}
		b.WriteString(")\n")
	}
	b.WriteByte('\n')
}

// writeWriteRules emits file-read* file-write* rules for read-write paths and files.
func writeWriteRules(b *strings.Builder, plan *SandboxPlan) {
	if plan.NoFSRestrict {
		return // already covered by writeReadRules
	}
	if len(plan.RWPaths) == 0 && len(plan.RWFiles) == 0 {
		return
	}
	b.WriteString(";; Read-write paths.\n")
	if len(plan.RWPaths) > 0 {
		b.WriteString("(allow file-read* file-write*\n")
		for _, p := range plan.RWPaths {
			fmt.Fprintf(b, "  (subpath %q)\n", p)
		}
		b.WriteString(")\n")
	}
	if len(plan.RWFiles) > 0 {
		b.WriteString("(allow file-read* file-write*\n")
		for _, f := range plan.RWFiles {
			fmt.Fprintf(b, "  (literal %q)\n", f)
		}
		b.WriteString(")\n")
	}
	b.WriteByte('\n')
}

// writeExecRules emits process-exec and file-map-executable rules.
// file-map-executable is needed for dyld to load shared libraries.
func writeExecRules(b *strings.Builder, plan *SandboxPlan) {
	if plan.NoFSRestrict || plan.NoExecRestrict {
		b.WriteString(";; Exec (unrestricted).\n")
		b.WriteString("(allow process-exec)\n")
		b.WriteString("(allow file-map-executable)\n\n")
		return
	}

	b.WriteString(";; Exec.\n")
	if len(plan.ExecPaths) > 0 {
		// Classify once to avoid duplicate os.Stat calls.
		execDirs, execFiles := splitDirsFiles(plan.ExecPaths)
		for _, op := range []string{"process-exec", "file-map-executable"} {
			fmt.Fprintf(b, "(allow %s\n", op)
			for _, p := range execDirs {
				fmt.Fprintf(b, "  (subpath %q)\n", p)
			}
			for _, p := range execFiles {
				fmt.Fprintf(b, "  (literal %q)\n", p)
			}
			b.WriteString(")\n")
		}
	}
	b.WriteByte('\n')
}

// writeDenyRules emits deny rules for hidden paths, deny-write paths, and
// deny-exec paths. In Seatbelt, deny rules override allow rules.
// Also emits file-write-unlink deny on ancestor directories to prevent
// rename-based escapes (move protection).
func writeDenyRules(b *strings.Builder, plan *SandboxPlan) {
	hasDenials := len(plan.HiddenPaths) > 0 || len(plan.DenyWritePaths) > 0 || len(plan.DenyExecPaths) > 0
	if !hasDenials {
		return
	}

	b.WriteString(";; Denials.\n")
	for _, p := range plan.HiddenPaths {
		fmt.Fprintf(b, "(deny file-read* file-write* (subpath %q))\n", p)
	}
	for _, p := range plan.DenyWritePaths {
		fmt.Fprintf(b, "(deny file-write* (subpath %q))\n", p)
	}
	for _, p := range plan.DenyExecPaths {
		fmt.Fprintf(b, "(deny process-exec (subpath %q))\n", p)
	}

	// Move protection: deny file-write-unlink on ancestor directories of
	// denied paths to prevent rename(2) escapes.
	ancestors := collectAncestors(plan.HiddenPaths, plan.DenyWritePaths, plan.DenyExecPaths)
	if len(ancestors) > 0 {
		b.WriteString(";; Move protection.\n")
		for _, a := range ancestors {
			fmt.Fprintf(b, "(deny file-write-unlink (literal %q))\n", a)
		}
	}
	b.WriteByte('\n')
}

// writeNetworkRules emits network rules based on the plan's network configuration.
func writeNetworkRules(b *strings.Builder, plan *SandboxPlan) {
	b.WriteString(";; Network.\n")

	if plan.UnrestrictedNet {
		b.WriteString("(allow network*)\n")
	} else if plan.ProxyEnabled {
		// Allow only outbound connections to the proxy port (proxy runs in the parent).
		fmt.Fprintf(b, "(allow network-outbound (remote ip \"localhost:%d\"))\n", plan.ProxyPort)
	} else if len(plan.AllowedIPs) > 0 {
		// Direct IP rules (no proxy needed for IP-only mode).
		for _, ip := range plan.AllowedIPs {
			if strings.Contains(ip, "/") {
				// CIDR: Seatbelt doesn't support CIDR natively.
				clog.Warnf("--ips %s: CIDR ranges are not enforced by Seatbelt on macOS; use individual IPs", ip)
			} else {
				fmt.Fprintf(b, "(allow network-outbound (remote ip \"%s:*\"))\n", ip)
			}
		}
	}

	// AF_UNIX socket blocking.
	if !plan.AllowUnixSockets {
		b.WriteString("(deny network* (socket-domain AF_UNIX))\n")
	}
	b.WriteByte('\n')
}

// collectAncestors returns a deduplicated, sorted list of ancestor directories
// for the given denied paths. Used for move protection.
func collectAncestors(pathSets ...[]string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, paths := range pathSets {
		for _, p := range paths {
			dir := filepath.Dir(p)
			for dir != "/" && dir != "." {
				if !seen[dir] {
					seen[dir] = true
					result = append(result, dir)
				}
				dir = filepath.Dir(dir)
			}
		}
	}
	sort.Strings(result)
	return result
}
