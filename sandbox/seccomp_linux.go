//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/upsun/curb/clog"
	"golang.org/x/sys/unix"
)

// seccomp_data field offsets (see linux/seccomp.h).
// These are stable kernel ABI with no golang.org/x/sys/unix equivalent.
const (
	seccompDataOffsetNR   = 0  // offsetof(struct seccomp_data, nr)
	seccompDataOffsetArch = 4  // offsetof(struct seccomp_data, arch)
	seccompDataOffsetArg0 = 16 // offsetof(struct seccomp_data, args[0])
)

// seccompFilter is the BPF program that blocks socket(AF_UNIX) and
// socketpair(AF_UNIX) with EPERM. All AF_UNIX sockets are blocked, not just
// abstract sockets, because seccomp cannot distinguish them (the address is
// only passed to bind/connect, not socket). This means sandboxed programs
// cannot create Unix domain sockets at all — including filesystem-path sockets
// within allowed paths.
//
// Built at init time from compile-time constants (unix.SYS_SOCKET etc. resolve
// per GOARCH via build tags).
//
// Program flow:
//
//	load arch
//	if arch != expected → allow
//	load syscall nr
//	if nr == socket → check_arg0
//	if nr == socketpair → check_arg0
//	→ allow
//	check_arg0: load args[0]
//	if args[0] == AF_UNIX → EPERM
//	→ allow
var seccompFilter = [10]unix.SockFilter{
	// 0: load arch
	bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataOffsetArch),
	// 1: if arch != expected → allow (jump to 9)
	bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, seccompAuditArch, 0, 7),
	// 2: load syscall nr
	bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataOffsetNR),
	// 3: if nr == socket → check_arg0 (jump to 6)
	bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_SOCKET, 2, 0),
	// 4: if nr == socketpair → check_arg0 (jump to 6)
	bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_SOCKETPAIR, 1, 0),
	// 5: allow (not socket/socketpair)
	bpfStmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW),
	// 6: load args[0] (domain)
	bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataOffsetArg0),
	// 7: if args[0] == AF_UNIX → EPERM (jump to 8), else allow (jump to 9)
	bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.AF_UNIX, 0, 1),
	// 8: return EPERM
	bpfStmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM)),
	// 9: allow
	bpfStmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW),
}

// enforceSeccomp installs a seccomp-bpf filter that blocks creation of
// AF_UNIX sockets (both socket and socketpair). This prevents sandboxed
// processes from communicating with host services via Unix domain sockets —
// particularly abstract sockets, which bypass all path-based enforcement
// (mount NS, Landlock).
//
// The filter is applied after all other sandbox setup (namespaces, mount NS,
// Landlock) but before exec. It is always-on as defense-in-depth, even when
// network namespace isolation already prevents abstract socket escape.
func enforceSeccomp(allowUnixSockets bool, log *clog.Logger) error {
	if allowUnixSockets {
		return nil
	}
	// This reads from the OS process env (inherited by the re-exec'd child),
	// not the filtered config env (which strips _CURB_ vars).
	if os.Getenv(TestNoSeccompEnvKey) == "1" {
		log.Warn("seccomp: disabled by %s", TestNoSeccompEnvKey)
		return nil
	}

	prog := unix.SockFprog{
		Len:    uint16(len(seccompFilter)),
		Filter: &seccompFilter[0],
	}

	// PR_SET_NO_NEW_PRIVS is required for unprivileged seccomp.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("seccomp: prctl(PR_SET_NO_NEW_PRIVS): %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER,
		uintptr(unsafe.Pointer(&prog)), 0, 0); err != nil {
		return fmt.Errorf("seccomp: prctl(PR_SET_SECCOMP): %w", err)
	}
	return nil
}

func bpfStmt(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, K: k}
}

func bpfJump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}
