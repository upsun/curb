# CLAUDE.md

`curb` is still in development. Anything can be changed without worrying about backwards compatibility: the interface, APIs, etc.

## Build & Test

```
make lint          # go fix -diff + golangci-lint (errcheck enabled)
go test ./...      # all tests; sandbox/ tests need Linux with user namespaces
go test ./sandbox/ -run TestCurb_FS_ -v  # run a subset
```

## Architecture

- `config/` — Config struct (FromFlags, MergeEnv), defaults (platform-split: `defaults_linux.go`, `defaults_darwin.go`), exclusion helpers, config file loading, profiles
- `sandbox/plan.go` — SandboxPlan, PlanBuilder interface, shared resolve* helpers, FSEnforcer interface
- `sandbox/plan_linux.go` — linuxPlanBuilder (namespace + Landlock enforcement selection)
- `sandbox/plan_darwin.go` — darwinPlanBuilder (Seatbelt enforcement, path canonicalization)
- `sandbox/plan_other.go` — degradedPlanBuilder (env-only fallback)
- `sandbox/parent_linux.go` — StartSandbox (re-exec into child namespace, signal forwarding)
- `sandbox/parent_darwin.go` — StartSandbox (sandbox-exec spawn, proxy, signal forwarding)
- `sandbox/child_linux.go` — ChildInit, enforcement dispatch via FSEnforcer (landlockEnforcer, fsEnforcers)
- `sandbox/mountfs_linux.go` — enforceMountNS (pivot_root allowlist), buildMountPlan, pivotRootEnforcer
- `sandbox/seatbelt_darwin.go` — generateSBPL (SBPL profile generation from SandboxPlan)
- `sandbox/capabilities_linux.go` — ProbeAll (user/net/mount NS with mount ops test, Landlock ABI)
- `sandbox/capabilities_darwin.go` — ProbeAll (Seatbelt probe, macOS version)
- `sandbox/proxy_handler.go` — buildProxyHandler, buildSOCKS5Server (shared by Linux and macOS parents)
- `proxy/` — HTTP proxy for domain filtering (CONNECT passthrough for HTTPS, Host header for plain HTTP), SOCKS5 proxy for non-HTTP TCP, connListener for fd-passing.
- `policy/` — DomainMatcher, IPMatcher, ValidateDomains/ValidateIPs, LandlockPaths, BuildLandlockRules
- `cmd/root.go` — CLI flag registration

## Key Design Decisions

- HTTP proxy is the sole network filter for HTTP/HTTPS, always active when `--domains` or `--ips` are specified. HTTPS uses CONNECT passthrough: the proxy checks the hostname from the CONNECT request, then tunnels the encrypted stream without terminating TLS. Plain HTTP is filtered via Host header inspection. Programs respecting proxy env vars get filtered access; programs ignoring them get no network (empty net NS). A SOCKS5 proxy handles non-HTTP TCP (e.g. SSH via ProxyCommand). Both proxy approaches filter on the CONNECT hostname or SOCKS5 destination, not on TLS SNI, so neither is affected by Encrypted Client Hello (ECH).
- The child runs TCP listeners on loopback and relays accepted connection fds to the parent via SCM_RIGHTS over a socketpair. FDs are tagged to dispatch to the correct proxy (HTTP or SOCKS5).
- Mount namespace (pivot_root) is the preferred FS enforcement: bind-mount allowed paths into a new root, pivot_root into it. Provides default-deny (ENOENT) and supports sub-path denials via overmount. Landlock layers on top when available for defense-in-depth. Landlock-only is a capable alternative (default-deny via EACCES) but cannot enforce sub-path denials (`!` exclusions under an allowed parent).
- Landlock requires different access rights for files vs directories. `DefaultROFiles` and `DefaultROPaths` are separate. `splitDirsFiles()` in plan.go classifies user-added paths via `os.Stat()`.
- `/etc` is not a blanket default. Only specific files/dirs are exposed (ssl, ca-certificates, ld.so, resolv.conf, hosts, passwd, etc.). Use `--read /etc` to restore full access.
- `/proc` is safe as default RO: user namespace blocks ptrace-guarded access across namespace boundaries.
- When the proxy is enabled, `NO_PROXY=localhost,127.0.0.1,::1` is set by default so sandbox-internal servers are reachable. `--host-loopback` suppresses this and forwards localhost traffic through the proxy to the host. User-provided `--env NO_PROXY=...` takes precedence.
- The SOCKS proxy is advertised via `ALL_PROXY`/`all_proxy` (HTTP/HTTPS still prefer `HTTP_PROXY`/`HTTPS_PROXY`). A user-provided value takes precedence, so `--env ALL_PROXY=` suppresses it — useful for HTTP-only workloads with clients that eagerly construct a SOCKS transport (e.g. httpx, which then needs the `httpx[socks]` extra). ssh routing does not use it (it has its own config).
- `--ips` allows connections to specific IP addresses or CIDR ranges. Works alongside or independently of `--domains`. IP-matched connections bypass domain filtering (forwarded directly on any port via SOCKS5 or CONNECT). In IPs-only mode (no `--domains`), DNS queries are not intercepted.
- `--unrestricted-net` skips network namespace creation entirely, allowing unrestricted network access while keeping FS sandboxing. Cannot be combined with `--domains` or `--ips`.
- `--inject-bearer HOST=SOURCE` and `--inject-header HOST=HEADER=SOURCE` (Linux) terminate TLS for `HOST` only and set a credential header (`Authorization: Bearer <token>`, or any header e.g. `x-api-key`), so the token never enters the sandbox. `--inject-bearer` is the same mechanism as `--inject-header` with the header fixed to `Authorization` and the value prefixed with `Bearer ` (`--inject-header` sets the header value to the resolved token verbatim, no prefix). The proxy holds the credential and a per-run CA; curb delivers a combined CA bundle (system roots + per-run CA) to the child via the standard CA env vars. `SOURCE` is `@ENV_VAR` (kept out of argv) or a literal. Settable via the flags, `CURB_INJECT_BEARER`/`CURB_INJECT_HEADER`, or the `inject-bearer:`/`inject-header:` config-file/profile keys (all merged additively); the `@ENV_VAR` form resolves at run time regardless of source. The CA key and token are parent-only — never serialized to the child. `@?VAR` is an optional source (inject only if set), and `VAR=?value` sets an env var only if it is set on the host; the `claude` profile uses both to seal `ANTHROPIC_API_KEY` out of Claude Code when present while staying a no-op for OAuth users.
- `--domains` validates input: rejects URLs (suggests bare domain), IP addresses (suggests `--ips`), invalid characters, and malformed wildcards. `--ips` validates that values parse as IP addresses or CIDR prefixes.
- `!` prefix in list flags removes from defaults AND actively denies via overmount when the path is under an allowed parent. `--read '!/path'` hides (tmpfs/dev-null), `--write '!/path'` makes read-only, `--exec '!/path'` makes noexec. `!*` clears all defaults (not deny-all). `\!` escapes literal `!`. Sub-path denials require mount NS; Landlock-only mode warns.
- HOME defaults to a private tmpDir. `--env HOME` passes through the host HOME; `--env HOME=/path` sets it explicitly. `~` and `$HOME` in config/profile paths both resolve to the **host** home (the shell's view), not the sandbox HOME — they are host-side shorthands. When sandbox HOME differs from host HOME and a path uses `~`, curb warns that the sandboxed program cannot reach those paths via its own `$HOME`. Built-in profiles include `HOME` in their env passthrough so sandbox HOME = host HOME and `~` paths align. See `docs/configuration.md` for full details.
- Exec is default-deny: `SystemExecPaths` is empty. Only the invoked command binary (auto-added), dynamic linker directories (`/lib`, `/lib64` on Linux, always included via `linkerExecPaths()` in `plan.go`), and profile/flag additions are executable. The `shell` profile restores system binary directories for interactive use; `curb -a bash` auto-applies it.

### Process lifecycle

- `Pdeathsig: SIGKILL` on re-exec'd child (`parent_linux.go`) and on ForkExec'd target (`child_linux.go`). When the parent dies, the kernel kills the child immediately.
- Signal escalation (`forwardSignals` in `process_unix.go`): first SIGINT/SIGTERM/SIGHUP is forwarded normally. A second termination signal force-kills the child. SIGHUP also starts a 3s kill timer (terminal is gone, user cannot send more signals).
- All three parent→child sites (parent_linux, parent_darwin, child_linux initLoop) use `forwardSignals`.

### macOS (Seatbelt)

- Apple's Seatbelt (`sandbox-exec`) provides kernel-enforced FS and network restrictions via SBPL profiles. Marked "deprecated" since macOS 10.7 but still functional and used by Codex, Homebrew, and Apple's own tools.
- No re-exec or namespaces. Seatbelt applies at spawn time: `sandbox-exec -p '<SBPL>' -- <command>`. The child and all descendants inherit the profile.
- FS enforcement via SBPL `file-read*`/`file-write*` rules. Sub-path denials use `(deny ...)` which overrides `(allow ...)`. Move protection via `(deny file-write-unlink)` on ancestor directories.
- Network: HTTP/SOCKS5 proxy on loopback is the sole HTTP/HTTPS filter. `--ips` works directly via Seatbelt IP rules.
- AF_UNIX socket blocking via `(deny network* (socket-domain AF_UNIX))` (Seatbelt, not seccomp).
- Path canonicalization is critical: macOS has `/var` -> `/private/var`, `/etc` -> `/private/etc`, `/tmp` -> `/private/tmp`. All paths are resolved via `filepath.EvalSymlinks` before SBPL generation.
- No PID isolation (macOS has no PID namespaces).
- Conservative mach-lookup allowlist: base services (opendirectoryd, logd, dirhelper) plus TLS/DNS services when network is enabled.

## Testing

- Integration tests in `sandbox/parent_linux_test.go` and `sandbox/proxy_test.go` build a `curb` binary and run it.
- Tests that need namespaces call `requireUserNS(t)`, `requireProxyNS(t)`, `requirePivotRoot(t)`, etc. to skip gracefully.
- `_CURB_TEST_NO_LANDLOCK=1` disables Landlock to test the mount-NS-only path.
- `_CURB_TEST_NO_MOUNT_NS=1` disables mount NS to test the Landlock-only path.
- `_CURB_TEST_NO_SECCOMP=1` disables the seccomp AF_UNIX filter.
- Tests that fail with exit 111 (curb setup failure) due to degraded mount NS retry with Landlock-only mode via `isSetupFailure()` + `landlockOnlyEnv()`.
- Network-dependent tests (external HTTP) use `requireExternalHTTP(t)` to skip gracefully.
- Write adversarial tests: try to escape each sandbox layer (env leaks, path traversal, exec bypass, namespace escapes).
- macOS Seatbelt tests in `sandbox/parent_darwin_test.go` and `sandbox/seatbelt_darwin_test.go` require macOS with sandbox-exec.
- `requireSeatbelt(t)` skips tests when sandbox-exec is unavailable.
- SBPL unit tests (`seatbelt_darwin_test.go`) test profile string generation without running sandbox-exec.
