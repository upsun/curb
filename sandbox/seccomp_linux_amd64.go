//go:build linux && amd64

package sandbox

import "golang.org/x/sys/unix"

const seccompAuditArch = unix.AUDIT_ARCH_X86_64
