# Comparison: curb vs sandbox-runtime

This document compares curb with Anthropic's
[sandbox-runtime](https://github.com/anthropics/sandbox-runtime) (srt),
which wraps [bubblewrap](https://github.com/containers/bubblewrap).
The comparison covers Linux only.

Both tools sandbox a subprocess with filesystem, network, and environment
restrictions. curb is a single Go binary with no runtime dependencies; srt
is a Node.js program that orchestrates bubblewrap, socat, and ripgrep. In
benchmarks, curb boots in ~12 ms using ~14 MB; srt takes ~104–198 ms using
~94–97 MB (see Performance below).

## Filesystem

The tools take opposite approaches to filesystem access.

**srt** starts with full read access and removes specific paths via a
denylist. A curated set of files is always hidden (`.bashrc`, `.gitconfig`,
`.git/hooks`, `.mcp.json`, IDE config dirs, etc.) -- this represents
accumulated knowledge of files an AI agent should not read. Write access is
denied by default; callers allowlist specific paths. srt uses ripgrep to
scan write paths for dangerous files (configurable depth, default 3 levels).
Glob patterns are expanded at startup on Linux (literal paths only).

**curb** starts with nothing accessible and adds paths via an allowlist.
Only listed paths exist inside the sandbox (ENOENT for everything else when
mount NS is active, EACCES with Landlock-only). Write access is also
deny-by-default. `!` prefix denials can hide specific paths under an
allowed parent (tmpfs overmount on dirs, `/dev/null` bind on files). Glob
patterns are supported on all path flags. curb additionally enforces
executable control via Landlock's EXECUTE right -- only listed binaries can
run.

srt's denylist is easier to use out of the box for broad compatibility.
curb's allowlist is stricter by default but requires the caller to specify
what should be accessible -- built-in profiles (see Configuration below)
reduce this burden for common toolchains.

## Network

Both tools run an HTTP proxy and a SOCKS5 proxy for domain filtering. The
sandboxed process gets an isolated network namespace (no external
interfaces); proxy environment variables route traffic through the filtering
proxies in the parent. The HTTP proxy handles HTTP/HTTPS (via CONNECT); the
SOCKS5 proxy handles other TCP (SSH, git protocol, database connections).
Both filter based on the CONNECT hostname or SOCKS5 destination, not on TLS
SNI, so neither is affected by Encrypted Client Hello (ECH). Programs that
ignore proxy env vars get no network.

Both use CONNECT passthrough for HTTPS: the proxy tunnels the encrypted
stream without terminating TLS.

**srt** bridges the proxies into the sandbox via Unix sockets and socat.

**curb** passes connection file descriptors from child to parent via
SCM_RIGHTS over a socketpair (no socat).

curb supports IP address and CIDR range filtering via `--ips` (e.g.
`--ips 10.0.0.0/8`). srt filters by domain only.

Both tools set `NO_PROXY` to bypass the proxy for localhost, so
sandbox-internal servers (e.g. dev servers started by the sandboxed
process) are reachable directly. curb additionally supports forwarding
localhost traffic to the host via `--host-loopback`; srt does not.

## Process isolation

Both tools create user namespaces, network namespaces, mount namespaces,
and PID namespaces. curb mounts a fresh `/proc` when mount NS is active, so
the sandboxed process only sees its own PIDs.

Both use seccomp BPF to block `AF_UNIX` socket creation, preventing the
sandboxed process from communicating with host services via Unix domain
sockets. This is important for abstract sockets (names starting with `\0`),
which have no filesystem path and bypass mount NS and Landlock. srt applies
the filter via a pre-built `apply-seccomp` binary after socat starts. curb
builds the BPF program in Go (10 instructions, zero heap allocation) and
applies it after FS enforcement, before exec. curb's filter is always-on as
defense-in-depth; `--allow-unix-sockets` disables it for programs that need
Unix sockets (Docker, databases via socket).

## Environment

srt inherits the full host environment and adds proxy variables
(`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, tool-specific variants like
`DOCKER_HTTP_PROXY`, `GRPC_PROXY`, etc.) plus `SANDBOX_RUNTIME=1`.

curb uses a deny-by-default model. Only safe variables (`PATH`, `TERM`,
`LANG`, `TZ`, `HOME`, etc.) are passed through. Additional variables are
added with `--env NAME` or `--env NAME=VALUE`. `--env '*'` passes the full
host environment.

## Configuration

Both tools work without any configuration file.

**srt** uses a single JSON config file (`~/.srt-settings.json` by default)
with network and filesystem settings. It also supports dynamic config
updates via a control file descriptor (JSON lines protocol), allowing the
caller to modify settings while the sandbox is running. srt has no concept
of reusable profiles -- config must be assembled per invocation.

**curb** uses YAML config files (`.curb.yaml`, auto-discovered by walking
up from the current directory) and composable profiles. Profiles are named
config bundles for common toolchains -- 9 are built in (`node`, `python`,
`php`, `go`, `rust`, `git`, `github`, `docker`, `claude-code`) and users
can add their own in `~/.config/curb/profiles/` or `/etc/curb/profiles/`.
Activated via `-p node,git`, `CURB_PROFILES=node,git`, or
`profiles: [node, git]` in `.curb.yaml`. Config layers merge in priority
order: profiles (lowest) -> config file -> CLI flags -> env vars (highest).

## Dependencies

| srt | curb |
|---|---|
| Node.js (v18+) | None |
| bubblewrap | (kernel syscalls) |
| socat | (kernel syscalls) |
| ripgrep | (kernel syscalls) |
| Pre-built seccomp binary | (kernel syscalls) |

curb has no external runtime dependencies on Linux. The seccomp filter is
built in Go.

## Performance

Benchmarks run via `make bench` (see `bench/bench_linux_test.go`).

### Time

End-to-end time including sandbox setup, command execution, and teardown.

| Benchmark | curb | srt (node) | srt (bun) |
|---|---|---|---|
| Boot (`true`) | ~12 ms | ~198 ms | ~104 ms |
| HTTP single request | ~17 ms | ~221 ms | ~117 ms |
| HTTP batch (10 requests) | ~59 ms | ~277 ms | ~181 ms |

The boot benchmark runs `/usr/bin/true` inside the sandbox, isolating
setup/teardown overhead. curb's single-process architecture (re-exec via
`clone()`) avoids the multi-process startup of srt (runtime -> bubblewrap
-> socat -> apply-seccomp -> command). The HTTP benchmarks run `curl`
against a local HTTP server with domain filtering enabled. srt is
benchmarked under both Node.js and Bun to separate JS runtime overhead
from sandboxing overhead.

Subtracting boot time gives per-request overhead: curb ~5 ms, srt ~7–8 ms.
Boot is the dominant difference for short-lived commands. Bun halves srt's
boot time but per-request overhead is similar. For long-running processes,
performance converges.

### Memory

Peak resident set size (RSS) of the sandbox process tree, reported by
`wait4()` rusage (includes the orchestrator and all reaped children).

| Benchmark | curb | srt (node) | srt (bun) |
|---|---|---|---|
| Boot (`true`) | ~14 MB | ~94 MB | ~97 MB |
| HTTP single request | ~15 MB | ~93 MB | ~101 MB |
| HTTP batch (10 requests) | ~15 MB | ~92 MB | ~101 MB |

curb is a single Go binary; srt starts a JS runtime, bubblewrap, socat,
and a seccomp helper, so its baseline RSS reflects the combined footprint
of those processes.

## Summary

- **Filesystem**: curb uses an allowlist (nothing accessible by default);
  srt uses a denylist (everything readable, specific files hidden). curb
  additionally controls which binaries can execute.
- **Network**: both use HTTP and SOCKS5 proxies for domain filtering (based
  on CONNECT hostname, not TLS SNI, so unaffected by ECH). Both use CONNECT
  passthrough for HTTPS. Both set `NO_PROXY` for sandbox-internal localhost.
  curb supports IP/CIDR filtering and host-localhost forwarding
  (`--host-loopback`); srt does not.
- **Seccomp**: both block AF_UNIX sockets via seccomp BPF. curb's filter is
  always-on with an opt-out (`--allow-unix-sockets`).
- **Environment**: srt inherits the full host environment; curb is
  deny-by-default.
- **Configuration**: srt uses JSON config with dynamic updates via control
  fd. curb uses YAML config files with composable profiles for common
  toolchains.
- **Dependencies**: curb is a single binary with no runtime dependencies.
  srt requires Node.js, bubblewrap, socat, and ripgrep.
