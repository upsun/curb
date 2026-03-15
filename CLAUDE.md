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
- `proxy/` — MITM proxy for HTTP/HTTPS domain filtering (ECH-proof): ephemeral CA, cert cache, CONNECT handler, connListener for fd-passing
- `netstack/` — gvisor userspace TCP/IP: DNS filtering, TLS SNI filtering, HTTP Host filtering, localhost forwarding
- `policy/` — DomainMatcher, IPMatcher, ValidateDomains/ValidateIPs, LandlockPaths, BuildLandlockRules
- `cmd/root.go` — CLI flag registration

## Key Design Decisions

- MITM proxy (`--proxy on`, default) is the primary network filter for HTTP/HTTPS. It terminates TLS in the parent process, making domain filtering immune to ECH. Programs respecting `HTTPS_PROXY` get filtered access; programs ignoring it get no network (empty net NS). TUN/TAP + netstack (`--tun always`) is an optional hardening layer. With `--proxy off`, netstack is the sole filter (requires TUN). This mirrors the FS model: mount NS is primary, Landlock hardens.
- An ephemeral ECDSA P-256 CA is generated per invocation. The combined CA bundle (system + ephemeral) is bind-mounted over the system CA path during pivot_root, and set via env vars (`SSL_CERT_FILE`, `CURL_CA_BUNDLE`, etc.).
- In proxy-only mode, the child runs a TCP listener on loopback and relays accepted connection fds to the parent via SCM_RIGHTS over the existing socketpair. In proxy+TUN mode, the proxy is a real TCP listener in the parent, reachable via netstack's localhost forwarding.
- Mount namespace (pivot_root) is the preferred FS enforcement: bind-mount allowed paths into a new root, pivot_root into it. Provides default-deny (ENOENT) and supports sub-path denials via overmount. Landlock layers on top when available for defense-in-depth. Landlock-only is a capable alternative (default-deny via EACCES) but cannot enforce sub-path denials (`!` exclusions under an allowed parent).
- Landlock requires different access rights for files vs directories. `DefaultROFiles` and `DefaultROPaths` are separate. `splitDirsFiles()` in plan.go classifies user-added paths via `os.Stat()`.
- `/etc` is not a blanket default. Only specific files/dirs are exposed (ssl, ca-certificates, ld.so, resolv.conf, hosts, passwd, etc.). Use `--read /etc` to restore full access.
- `/proc` is safe as default RO: user namespace blocks ptrace-guarded access across namespace boundaries.
- `--domains localhost` enables localhost forwarding (internally sets `AllowLocalhost` on the plan).
- `--ips` allows connections to specific IP addresses or CIDR ranges. Works alongside or independently of `--domains`. IP-matched connections bypass port restrictions and domain filtering (forwarded directly on any port). In IPs-only mode (no `--domains`), a deny-all DNS filter returns REFUSED immediately.
- `--unrestricted-net` skips network namespace creation entirely, allowing unrestricted network access while keeping FS sandboxing. Cannot be combined with `--domains` or `--ips`.
- `--domains` validates input: rejects URLs (suggests bare domain), IP addresses (suggests `--ips`), invalid characters, and malformed wildcards. `--ips` validates that values parse as IP addresses or CIDR prefixes.
- `!` prefix in list flags removes from defaults AND actively denies via overmount when the path is under an allowed parent. `--read '!/path'` hides (tmpfs/dev-null), `--write '!/path'` makes read-only, `--exec '!/path'` makes noexec. `!*` clears all defaults (not deny-all). `\!` escapes literal `!`. Sub-path denials require mount NS; Landlock-only mode warns.

## Testing

- Integration tests in `sandbox/parent_linux_test.go` and `sandbox/proxy_test.go` build a `curb` binary and run it.
- Tests that need namespaces call `requireUserNS(t)`, `requireNetNS(t)`, `requireProxyNS(t)`, `requirePivotRoot(t)`, etc. to skip gracefully.
- Netstack-specific tests must use `--proxy off` to bypass the proxy (default is `--proxy on`).
- `_CURB_TEST_NO_LANDLOCK=1` disables Landlock to test the mount-NS-only path.
- `_CURB_TEST_NO_MOUNT_NS=1` disables mount NS to test the Landlock-only path.
- Tests that fail with exit 111 (curb setup failure) due to degraded mount NS retry with Landlock-only mode via `isSetupFailure()` + `landlockOnlyEnv()`.
- Network-dependent tests (external HTTP) use `requireExternalHTTP(t)` to skip gracefully.
- Write adversarial tests: try to escape each sandbox layer (env leaks, path traversal, exec bypass, namespace escapes).
