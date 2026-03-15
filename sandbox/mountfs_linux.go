//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/upsun/curb/clog"
)

// mountEntry represents a single bind-mount in the new root.
type mountEntry struct {
	src           string
	isFile        bool
	isDev         bool // Character or block device node.
	readOnly      bool
	noExec        bool
	userRequested bool // Explicitly requested by the user (not a default/auto path).
}

// buildMountPlan collects, deduplicates, and sorts mount entries shortest-first.
// When execPaths is non-empty, all other paths get MS_NOEXEC; exec paths override.
// When execPaths is empty (no exec restriction), noExec is false for all entries.
func buildMountPlan(cfg *ChildConfig) []mountEntry {
	hasExecRestrict := len(cfg.ExecPaths) > 0

	userSet := make(map[string]bool, len(cfg.UserPaths))
	for _, p := range cfg.UserPaths {
		userSet[p] = true
	}

	entries := make(map[string]*mountEntry)

	// Helper to add an entry, merging permissions if already present.
	// isFile is determined later by os.Stat, not by the caller.
	add := func(path string, readOnly, noExec bool) {
		if e, ok := entries[path]; ok {
			// RW wins over RO.
			if !readOnly {
				e.readOnly = false
			}
			// noExec=false wins (exec-allowed overrides).
			if !noExec {
				e.noExec = false
			}
			return
		}
		entries[path] = &mountEntry{
			src:      path,
			readOnly: readOnly,
			noExec:   noExec,
		}
	}

	// RO paths.
	for _, p := range cfg.ROPaths {
		add(p, true, hasExecRestrict)
	}
	for _, p := range cfg.ROFiles {
		add(p, true, hasExecRestrict)
	}
	// RW paths.
	for _, p := range cfg.RWPaths {
		add(p, false, hasExecRestrict)
	}
	for _, p := range cfg.RWFiles {
		add(p, false, hasExecRestrict)
	}
	// Exec paths: noExec=false, readOnly=true by default.
	for _, p := range cfg.ExecPaths {
		add(p, true, false)
	}

	// Filter out entries whose source doesn't exist.
	// Skip /proc: enforceMountNS mounts a fresh procfs unconditionally.
	var result []mountEntry
	for _, e := range entries {
		if e.src == "/proc" {
			continue
		}
		info, err := os.Stat(e.src)
		if err != nil {
			continue
		}
		e.isFile = !info.IsDir()
		e.isDev = info.Mode()&os.ModeDevice != 0
		e.userRequested = userSet[e.src]
		result = append(result, *e)
	}

	// Filter entries subsumed by a parent directory with identical mount
	// flags. When --read /etc is specified, default files like
	// /etc/resolv.conf are already accessible through the parent bind mount
	// and don't need separate mount entries. Creating mount points for them
	// inside the read-only parent would fail.
	dirSet := make(map[string]mountEntry, len(result))
	for _, e := range result {
		if !e.isFile {
			dirSet[e.src] = e
		}
	}
	filtered := result[:0]
	for _, e := range result {
		if !isSubsumed(dirSet, e) {
			filtered = append(filtered, e)
		}
	}
	result = filtered

	// Sort by path length (shortest first) so parents are mounted before children.
	sort.Slice(result, func(i, j int) bool {
		if len(result[i].src) != len(result[j].src) {
			return len(result[i].src) < len(result[j].src)
		}
		return result[i].src < result[j].src
	})

	return result
}

// isSubsumed reports whether a parent directory in dirs provides identical
// mount flags (readOnly, noExec), making child redundant. Device entries are
// never subsumed because they need their own mount without MS_NODEV.
func isSubsumed(dirs map[string]mountEntry, child mountEntry) bool {
	if child.isDev {
		return false
	}
	path := child.src
	for {
		parent := filepath.Dir(path)
		if parent == path {
			return false
		}
		if e, ok := dirs[parent]; ok {
			return e.readOnly == child.readOnly && e.noExec == child.noExec
		}
		path = parent
	}
}

// enforceMountNS restricts filesystem access by building a new root from
// allowed paths using bind mounts and pivot_root.
func enforceMountNS(cfg *ChildConfig) error {
	if err := prepareMountNS(); err != nil {
		return fmt.Errorf("setting slave propagation: %w", err)
	}

	// Create tmpfs as new root.
	const newRoot = "/tmp/curb-newroot"
	if err := os.MkdirAll(newRoot, 0o755); err != nil {
		return fmt.Errorf("creating new root: %w", err)
	}
	if err := syscall.Mount("tmpfs", newRoot, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "size=1M"); err != nil {
		return fmt.Errorf("mounting tmpfs on new root: %w", err)
	}

	// Build the mount plan.
	mounts := buildMountPlan(cfg)

	// Bind-mount allowed paths into the new root.
	for _, m := range mounts {
		dst := filepath.Join(newRoot, m.src)
		if m.isFile {
			// Create parent directory and empty file for file bind mounts.
			// Skip creation if the file (or symlink) already exists, e.g.
			// from a parent bind mount that was remounted read-only.
			if _, statErr := os.Lstat(dst); statErr != nil {
				if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
					return fmt.Errorf("creating parent for %s: %w", m.src, err)
				}
				f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0o644)
				if err != nil {
					return fmt.Errorf("creating mount point for %s: %w", m.src, err)
				}
				_ = f.Close()
			}
		} else {
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return fmt.Errorf("creating mount point for %s: %w", m.src, err)
			}
		}
		if err := syscall.Mount(m.src, dst, "", syscall.MS_BIND, ""); err != nil {
			// Bind-mount failure is non-fatal: the path will be absent from
			// the new root (ENOENT), which is strictly more restrictive.
			// This handles paths that AppArmor blocks or that have
			// incompatible mount properties (e.g. kernel pseudo-filesystems
			// mounted underneath by EDR tools).
			if m.userRequested {
				clog.Warnf("skipping %s: bind mount failed (%v); path will not be available in the sandbox", m.src, err)
			}
			_ = os.Remove(dst)
			continue
		}

		// Remount with desired flags. The kernel ignores MS_RDONLY on the
		// initial bind mount, so a remount is required.
		// MS_NODEV is skipped for device nodes: the kernel blocks open()
		// on character/block devices when MNT_NODEV is set on the mount.
		flags := uintptr(syscall.MS_REMOUNT | syscall.MS_BIND | syscall.MS_NOSUID)
		if !m.isDev {
			flags |= syscall.MS_NODEV
		}
		if m.readOnly {
			flags |= syscall.MS_RDONLY
		}
		if m.noExec {
			flags |= syscall.MS_NOEXEC
		}
		if err := syscall.Mount("", dst, "", flags, ""); err != nil {
			return fmt.Errorf("remounting %s: %w", m.src, err)
		}
	}

	// Overmount denied read paths: empty tmpfs for directories, /dev/null for files.
	// This runs before pivot_root, so host paths (e.g. /dev/null) are still accessible.
	for _, p := range cfg.HiddenPaths {
		dst := filepath.Join(newRoot, p)
		info, err := os.Stat(dst)
		if err != nil {
			continue // Path doesn't exist in new root (not under any allowed path).
		}
		if info.IsDir() {
			if err := syscall.Mount("tmpfs", dst, "tmpfs",
				syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "size=0"); err != nil {
				return fmt.Errorf("hiding %s: %w", p, err)
			}
		} else {
			if err := syscall.Mount("/dev/null", dst, "", syscall.MS_BIND, ""); err != nil {
				return fmt.Errorf("hiding %s: %w", p, err)
			}
		}
	}

	// Overmount denied write paths (MS_RDONLY) and exec paths (MS_NOEXEC).
	if err := overmountDeny(newRoot, cfg.DenyWritePaths, syscall.MS_RDONLY, "deny-write"); err != nil {
		return err
	}
	if err := overmountDeny(newRoot, cfg.DenyExecPaths, syscall.MS_NOEXEC, "deny-exec"); err != nil {
		return err
	}

	// Bind-mount combined CA bundle over the system CA path so the proxy's
	// ephemeral CA is trusted by all programs in the sandbox.
	if cfg.CACertFile != "" && cfg.CACertMountDst != "" {
		dst := filepath.Join(newRoot, cfg.CACertMountDst)
		if _, err := os.Stat(dst); err == nil {
			if err := syscall.Mount(cfg.CACertFile, dst, "", syscall.MS_BIND, ""); err != nil {
				return fmt.Errorf("bind-mounting CA bundle: %w", err)
			}
			flags := uintptr(syscall.MS_REMOUNT | syscall.MS_BIND | syscall.MS_RDONLY | syscall.MS_NOSUID | syscall.MS_NODEV)
			if err := syscall.Mount("", dst, "", flags, ""); err != nil {
				return fmt.Errorf("remounting CA bundle read-only: %w", err)
			}
		}
	}

	// Mount /proc (best-effort: fails on hidepid=invisible and similar restrictions).
	procDst := filepath.Join(newRoot, "proc")
	if err := os.MkdirAll(procDst, 0o755); err != nil {
		return fmt.Errorf("creating /proc: %w", err)
	}
	if err := syscall.Mount("proc", procDst, "proc",
		syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		// Not fatal: /proc is useful but not required for FS enforcement.
		_ = os.Remove(procDst)
	}

	// Mount /dev/pts if it's in the allowed paths.
	devptsDst := filepath.Join(newRoot, "dev", "pts")
	if _, err := os.Stat(devptsDst); err == nil {
		// Remount devpts with newinstance so the child gets its own PTY namespace.
		_ = syscall.Mount("devpts", devptsDst, "devpts",
			syscall.MS_NOSUID|syscall.MS_NOEXEC, "newinstance,ptmxmode=0666")
	}

	// Synthesize /etc/passwd and /etc/group so that UID 0 (the user
	// namespace mapping) resolves to the original username, not "root".
	if err := synthesizePasswd(cfg, newRoot); err != nil {
		return err
	}

	// Save CWD before pivot.
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "/"
	}

	// Create old_root mount point for pivot_root.
	oldRoot := filepath.Join(newRoot, ".old_root")
	if err := os.MkdirAll(oldRoot, 0o755); err != nil {
		return fmt.Errorf("creating old root: %w", err)
	}

	// pivot_root.
	if err := syscall.PivotRoot(newRoot, oldRoot); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := syscall.Chdir("/"); err != nil {
		return fmt.Errorf("chdir /: %w", err)
	}

	// Unmount old root.
	if err := syscall.Unmount("/.old_root", syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("unmounting old root: %w", err)
	}
	_ = os.Remove("/.old_root")

	// Restore CWD.
	if err := syscall.Chdir(cwd); err != nil {
		// CWD may not exist in new root; fall back to /.
		_ = syscall.Chdir("/")
	}

	return nil
}

// synthesizePasswd creates synthetic /etc/passwd and /etc/group files that map
// UID/GID 0 to the original username. Inside a user namespace the host UID is
// mapped to 0, so without this, tools resolve UID 0 to "root".
func synthesizePasswd(cfg *ChildConfig, newRoot string) error {
	username, home, shell := "user", "/", "/bin/sh"
	for _, e := range cfg.Env {
		if k, v, ok := strings.Cut(e, "="); ok {
			switch k {
			case "USER":
				username = v
			case "HOME":
				home = v
			case "SHELL":
				shell = v
			}
		}
	}

	type synthFile struct {
		path    string
		content string
	}
	files := []synthFile{
		{
			path: filepath.Join(newRoot, "etc", "passwd"),
			content: fmt.Sprintf("%s:x:0:0::%s:%s\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
				username, home, shell),
		},
		{
			path:    filepath.Join(newRoot, "etc", "group"),
			content: fmt.Sprintf("%s:x:0:\nnogroup:x:65534:\n", username),
		},
	}

	for _, f := range files {
		if _, err := os.Stat(f.path); err != nil {
			continue // Not in the mount plan.
		}
		// Write temp file to the tmpfs root (always writable), not next to the
		// target which may be inside a read-only parent bind mount.
		tmp := filepath.Join(newRoot, ".synth-"+filepath.Base(f.path))
		if err := os.WriteFile(tmp, []byte(f.content), 0o644); err != nil {
			return fmt.Errorf("writing synthetic %s: %w", filepath.Base(f.path), err)
		}
		if err := syscall.Mount(tmp, f.path, "", syscall.MS_BIND, ""); err != nil {
			return fmt.Errorf("mounting synthetic %s: %w", filepath.Base(f.path), err)
		}
		_ = os.Remove(tmp) // Bind mount holds the inode; remove the visible name.
		flags := uintptr(syscall.MS_REMOUNT | syscall.MS_BIND | syscall.MS_RDONLY | syscall.MS_NOSUID | syscall.MS_NODEV)
		if err := syscall.Mount("", f.path, "", flags, ""); err != nil {
			return fmt.Errorf("remounting synthetic %s: %w", filepath.Base(f.path), err)
		}
	}
	return nil
}

// overmountDeny self-bind-mounts each path and remounts with the given extra
// flag (e.g. MS_RDONLY or MS_NOEXEC). Paths that don't exist are skipped.
// MS_RDONLY is always included: deny paths are at least read-only (deny-write
// adds it explicitly; deny-exec must preserve it to avoid widening permissions).
func overmountDeny(newRoot string, paths []string, extraFlag uintptr, label string) error {
	for _, p := range paths {
		dst := filepath.Join(newRoot, p)
		if _, err := os.Stat(dst); err != nil {
			continue
		}
		if err := syscall.Mount(dst, dst, "", syscall.MS_BIND, ""); err != nil {
			return fmt.Errorf("%s %s: %w", label, p, err)
		}
		flags := uintptr(syscall.MS_REMOUNT | syscall.MS_BIND | syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_RDONLY)
		flags |= extraFlag
		if err := syscall.Mount("", dst, "", flags, ""); err != nil {
			return fmt.Errorf("%s remount %s: %w", label, p, err)
		}
	}
	return nil
}
