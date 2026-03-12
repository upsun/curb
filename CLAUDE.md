# CLAUDE.md

## Build & Test

```
make lint          # go fix -diff + golangci-lint (errcheck enabled)
go test ./...      # all tests; sandbox/ tests need Linux with user namespaces
go test ./sandbox/ -run TestCurb_FS_ -v  # run a subset
```

gvisor dependency must use the `go` branch (not `master`). The `master` branch has `.tmpl.s` files that break `go build`.

## Architecture

- `config/` — Config struct (FromFlags, MergeEnv), defaults (paths, env vars), exclusion helpers (ParseExclusions, ApplyExclusions)
- `sandbox/plan.go` — SandboxPlan, BuildPlan (merges config + capabilities into enforcement plan)
- `sandbox/parent_linux.go` — StartSandbox, re-exec into child namespace, signal forwarding
- `sandbox/child_linux.go` — ChildInit, enforcement dispatch (pivot_root then Landlock)
- `sandbox/mountfs_linux.go` — enforceMountNS (pivot_root allowlist), buildMountPlan
- `sandbox/capabilities_linux.go` — ProbeAll (user/net/mount NS with mount ops test, TUN, Landlock ABI)
- `netstack/` — gvisor userspace TCP/IP: DNS filtering, TLS SNI filtering, HTTP Host filtering, localhost forwarding
- `policy/` — DomainMatcher, LandlockPaths, BuildLandlockRules
- `cmd/root.go` — CLI flag registration

## Key Design Decisions

- Mount namespace (pivot_root) is the preferred FS enforcement: bind-mount allowed paths into a new root, pivot_root into it. Provides default-deny (ENOENT) and supports sub-path denials via overmount. Landlock layers on top when available for defense-in-depth. Landlock-only is a capable alternative (default-deny via EACCES) but cannot enforce sub-path denials (`!` exclusions under an allowed parent).
- Landlock requires different access rights for files vs directories. `DefaultROFiles` and `DefaultROPaths` are separate. `splitDirsFiles()` in plan.go classifies user-added paths via `os.Stat()`.
- `/etc` is not a blanket default. Only specific files/dirs are exposed (ssl, ca-certificates, ld.so, resolv.conf, hosts, passwd, etc.). Use `--read /etc` to restore full access.
- `/proc` is safe as default RO: user namespace blocks ptrace-guarded access across namespace boundaries.
- `--domains localhost` enables localhost forwarding (internally sets `AllowLocalhost` on the plan).
- `!` prefix in list flags removes from defaults AND actively denies via overmount when the path is under an allowed parent. `--read '!/path'` hides (tmpfs/dev-null), `--write '!/path'` makes read-only, `--exec '!/path'` makes noexec. `!*` clears all defaults (not deny-all). `\!` escapes literal `!`. Sub-path denials require mount NS; Landlock-only mode warns.

## Testing

- Integration tests in `sandbox/parent_linux_test.go` build a `curb` binary and run it.
- Tests that need namespaces call `requireUserNS(t)`, `requireNetNS(t)`, `requirePivotRoot(t)`, etc. to skip gracefully.
- `_CURB_TEST_NO_LANDLOCK=1` disables Landlock to test the mount-NS-only path.
- Write adversarial tests: try to escape each sandbox layer (env leaks, path traversal, exec bypass, namespace escapes).
