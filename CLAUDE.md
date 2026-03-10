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
- `sandbox/child_linux.go` — ChildInit, Landlock enforcement, mount namespace setup
- `sandbox/capabilities_linux.go` — ProbeAll (user/net/mount NS, TUN, Landlock ABI)
- `netstack/` — gvisor userspace TCP/IP: DNS filtering, TLS SNI filtering, HTTP Host filtering, localhost forwarding
- `policy/` — DomainMatcher, LandlockPaths, BuildLandlockRules
- `cmd/root.go` — CLI flag registration

## Key Design Decisions

- Landlock requires different access rights for files vs directories. `DefaultROFiles` and `DefaultROPaths` are separate. `splitDirsFiles()` in plan.go classifies user-added paths via `os.Stat()`.
- `/etc` is not a blanket default. Only specific files/dirs are exposed (ssl, ca-certificates, ld.so, resolv.conf, hosts, passwd, etc.). Use `--read /etc` to restore full access.
- `/proc` is safe as default RO: user namespace blocks ptrace-guarded access across namespace boundaries.
- `--domains localhost` enables localhost forwarding (internally sets `AllowLocalhost` on the plan).
- `!` prefix in list flags removes defaults; `!*` removes all defaults; `\!` escapes literal `!`.

## Testing

- Integration tests in `sandbox/parent_linux_test.go` build a `curb` binary and run it.
- Tests that need namespaces call `requireUserNS(t)`, `requireNetNS(t)`, etc. to skip gracefully.
- Write adversarial tests: try to escape each sandbox layer (env leaks, path traversal, exec bypass, namespace escapes).
