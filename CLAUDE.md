# CLAUDE.md

## Build & Test

```
make lint          # go fix -diff + golangci-lint (errcheck enabled)
go test ./...      # all tests; sandbox/ tests need Linux with user namespaces
go test ./sandbox/ -run TestCurb_FS_ -v  # run a subset
```

gvisor dependency must use the `go` branch (not `master`). The `master` branch has `.tmpl.s` files that break `go build`.

## Architecture

- `config/` — Config struct (FromFlags, MergeEnv), defaults (platform-split: `defaults_linux.go`, `defaults_darwin.go`), exclusion helpers, config file loading, profiles
- `sandbox/plan.go` — SandboxPlan, PlanBuilder interface, shared resolve* helpers, FSEnforcer interface
- `sandbox/plan_linux.go` — linuxPlanBuilder (namespace + Landlock enforcement selection)
- `sandbox/plan_darwin.go` — darwinPlanBuilder (Seatbelt enforcement, path canonicalization)
- `sandbox/plan_other.go` — degradedPlanBuilder (env-only fallback)
- `sandbox/parent_linux.go` — StartSandbox (re-exec into child namespace, signal forwarding)
- `sandbox/parent_darwin.go` — StartSandbox (sandbox-exec spawn, MITM proxy, signal forwarding)
- `sandbox/child_linux.go` — ChildInit, enforcement dispatch via FSEnforcer (landlockEnforcer, fsEnforcers)
- `sandbox/mountfs_linux.go` — enforceMountNS (pivot_root allowlist), buildMountPlan, pivotRootEnforcer
- `sandbox/seatbelt_darwin.go` — generateSBPL (SBPL profile generation from SandboxPlan)
- `sandbox/capabilities_linux.go` — ProbeAll (user/net/mount NS with mount ops test, TUN, Landlock ABI)
- `sandbox/capabilities_darwin.go` — ProbeAll (Seatbelt probe, macOS version)
- `sandbox/proxy_handler.go` — buildProxyHandler (shared by Linux and macOS parents)
- `proxy/` — MITM proxy for HTTP/HTTPS domain filtering (works regardless of ECH): ephemeral CA, cert cache, CONNECT handler, connListener for fd-passing. CA bundle paths platform-split (`cabundle_linux.go`, `cabundle_darwin.go`).
- `netstack/` — gvisor userspace TCP/IP (Linux only): DNS filtering, HTTP Host filtering, localhost forwarding. Port 443 is blocked (use proxy for HTTPS).
- `policy/` — DomainMatcher, IPMatcher, ValidateDomains/ValidateIPs, LandlockPaths, BuildLandlockRules
- `cmd/root.go` — CLI flag registration

## Key Design Decisions

- MITM proxy is the primary network filter for HTTP/HTTPS, always active when `--domains` or `--ips` are specified. It terminates TLS in the parent process, so domain filtering works regardless of Encrypted Client Hello (ECH). Programs respecting `HTTPS_PROXY` get filtered access; programs ignoring it get no network (empty net NS). TUN/TAP + netstack (`--tun`) is an optional hardening layer that provides DNS and HTTP filtering at the packet level; port 443 is blocked at the TUN layer (HTTPS must go through the proxy). If TUN is requested but unavailable, the proxy provides filtering alone (degraded warning). This mirrors the FS model: mount NS is primary, Landlock hardens.
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
- HOME defaults to a private tmpDir. `--env HOME` passes through the host HOME; `--env HOME=/path` sets it explicitly. `~` in config/profile paths resolves to the sandbox HOME (not the host home). Built-in profiles include `HOME` in their env passthrough so `~` paths resolve correctly. See `docs/configuration.md` for full details.

### Process lifecycle

- `Pdeathsig: SIGKILL` on re-exec'd child (`parent_linux.go`) and on ForkExec'd target (`child_linux.go`). When the parent dies, the kernel kills the child immediately.
- Signal escalation (`forwardSignals` in `process_unix.go`): first SIGINT/SIGTERM/SIGHUP is forwarded normally. A second termination signal force-kills the child. SIGHUP also starts a 3s kill timer (terminal is gone, user cannot send more signals).
- All three parent→child sites (parent_linux, parent_darwin, child_linux initLoop) use `forwardSignals`.

### macOS (Seatbelt)

- Apple's Seatbelt (`sandbox-exec`) provides kernel-enforced FS and network restrictions via SBPL profiles. Marked "deprecated" since macOS 10.7 but still functional and used by Codex, Homebrew, and Apple's own tools.
- No re-exec or namespaces. Seatbelt applies at spawn time: `sandbox-exec -p '<SBPL>' -- <command>`. The child and all descendants inherit the profile.
- FS enforcement via SBPL `file-read*`/`file-write*` rules. Sub-path denials use `(deny ...)` which overrides `(allow ...)`. Move protection via `(deny file-write-unlink)` on ancestor directories.
- Network: MITM proxy on loopback is the sole HTTP/HTTPS filter (no TUN/netstack on macOS). `--ips` works directly via Seatbelt IP rules.
- AF_UNIX socket blocking via `(deny network* (socket-domain AF_UNIX))` (Seatbelt, not seccomp).
- Path canonicalization is critical: macOS has `/var` -> `/private/var`, `/etc` -> `/private/etc`, `/tmp` -> `/private/tmp`. All paths are resolved via `filepath.EvalSymlinks` before SBPL generation.
- No PID isolation (macOS has no PID namespaces).
- Conservative mach-lookup allowlist: base services (opendirectoryd, logd, dirhelper) plus TLS/DNS services when network is enabled.

## Testing

- Integration tests in `sandbox/parent_linux_test.go` and `sandbox/proxy_test.go` build a `curb` binary and run it.
- Tests that need namespaces call `requireUserNS(t)`, `requireNetNS(t)`, `requireProxyNS(t)`, `requirePivotRoot(t)`, etc. to skip gracefully.
- Netstack-specific tests use `--tun` to enable TUN alongside the proxy. Tests that need to exercise the TUN path directly use `--noproxy '*'` with curl to bypass proxy env vars.
- `_CURB_TEST_NO_LANDLOCK=1` disables Landlock to test the mount-NS-only path.
- `_CURB_TEST_NO_MOUNT_NS=1` disables mount NS to test the Landlock-only path.
- `_CURB_TEST_NO_SECCOMP=1` disables the seccomp AF_UNIX filter.
- Tests that fail with exit 111 (curb setup failure) due to degraded mount NS retry with Landlock-only mode via `isSetupFailure()` + `landlockOnlyEnv()`.
- Network-dependent tests (external HTTP) use `requireExternalHTTP(t)` to skip gracefully.
- Write adversarial tests: try to escape each sandbox layer (env leaks, path traversal, exec bypass, namespace escapes).
- macOS Seatbelt tests in `sandbox/parent_darwin_test.go` and `sandbox/seatbelt_darwin_test.go` require macOS with sandbox-exec.
- `requireSeatbelt(t)` skips tests when sandbox-exec is unavailable.
- SBPL unit tests (`seatbelt_darwin_test.go`) test profile string generation without running sandbox-exec.
