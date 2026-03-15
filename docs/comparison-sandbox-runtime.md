# Comparison: curb vs sandbox-runtime

This document compares curb with Anthropic's
[sandbox-runtime](https://github.com/anthropics/sandbox-runtime) (srt),
which wraps [bubblewrap](https://github.com/containers/bubblewrap).
The comparison covers Linux only.

## Overview

Both projects sandbox a subprocess with filesystem, network, and environment
restrictions. Either can be used to sandbox short-lived commands or
longer-running processes, though their architectures lead to different
tradeoffs in each case.

Key practical differences:

- curb starts ~6x faster (35 ms vs 208 ms), which matters when sandboxing
  many short-lived commands (e.g. repeated tool calls in an agent loop).
- curb's default network filtering uses a MITM proxy (like srt), but
  programs that ignore `HTTPS_PROXY` get no network (isolated namespace)
  rather than failing silently. With `--tun always`, curb additionally
  provides transparent packet-level filtering for non-HTTP programs.
- curb has no external dependencies (no bubblewrap, socat, ripgrep, or
  Node.js runtime to install).
- Both isolate the PID namespace when available. curb skips PID NS in
  proxy-only mode (the Go runtime must stay alive for the fd-passing
  accept loop). srt's PID namespace requires `CLONE_NEWPID`, which may
  not be available in nested or restricted environments.
- srt ships a curated denylist of files an AI agent should not read
  (`.bashrc`, `.gitconfig`, `.git/hooks`, etc.). curb's allow-only model
  is stricter but requires the caller to specify what should be accessible.

## Filesystem

|  | srt | curb |
|---|---|---|
| Mechanism | bubblewrap bind mounts + tmpfs overmounts | Mount namespace (pivot_root) + Landlock LSM (kernel 5.13+) |
| Read model | Allow-all + denylist (scans for dangerous files with ripgrep) | Deny-all + allowlist (only listed paths are accessible) |
| Write model | Deny-all + allowlist (`allowWrite`) | Deny-all + allowlist (`--write`) |
| Exec control | None | Landlock `EXECUTE` right: only listed binaries can run |
| Hidden paths | tmpfs overmount on denied dirs, `/dev/null` bind on denied files | `!` denials: tmpfs overmount on dirs, `/dev/null` bind on files; fresh `/tmp` and `/dev` |
| Glob patterns | Literal paths only (Linux) | Supported on all path flags |
| Host side effects | Creates ghost mount-point files for non-existent denied paths (requires cleanup) | None |

**srt advantage**: srt's denylist includes a curated set of dangerous files
(`.bashrc`, `.gitconfig`, `.git/hooks`, `.mcp.json`, IDE config dirs) that
represents accumulated knowledge of files an AI agent should not read. curb's
allow-only model avoids needing this list, but users must assemble their own
allowlist for each use case.

## Network

|  | srt | curb (proxy, default) | curb (TUN, `--tun always`) |
|---|---|---|---|
| Mechanism | `bwrap --unshare-net`, HTTP + SOCKS5 proxies via Unix sockets + socat | MITM proxy in parent, connection fds passed via SCM_RIGHTS | MITM proxy + TAP device + userspace TCP/IP (gvisor netstack) |
| Traffic routing | Via `HTTP_PROXY` / `ALL_PROXY` env vars | Via `HTTPS_PROXY` / `HTTP_PROXY` env vars | Proxy env vars + transparent TAP for non-proxy traffic |
| Non-proxy programs | No network (no interface) | No network (empty net NS, loopback only) | Domain-filtered via netstack (DNS, SNI, Host) |
| Protocol coverage | HTTP via HTTP proxy, other TCP via SOCKS5 | HTTP/HTTPS only | All IP traffic (full TCP/IP stack) |
| Filtering signal | CONNECT hostname / SOCKS5 destination | CONNECT hostname / HTTP Host (TLS terminated) | Proxy + DNS + TLS SNI + HTTP Host |
| ECH handling | N/A (proxy sees hostname) | N/A (proxy terminates TLS) | Netstack: strip, allow, or deny ECH |
| Localhost forwarding | No | `--domains localhost` | `--domains localhost` |

Both curb (default) and srt use HTTP proxies for domain filtering. The key
differences: curb's proxy terminates TLS (MITM), seeing the actual request
regardless of ECH. srt's proxy relies on the CONNECT hostname without
inspecting TLS content. curb's `--tun always` mode adds transparent
packet-level filtering for programs that ignore proxy env vars.

## Process isolation

|  | srt | curb |
|---|---|---|
| PID namespace | Yes (`bwrap --unshare-pid` + fresh `/proc`) | Yes (fresh `/proc` where mount NS is active) |
| User namespace | Implicit via bubblewrap | Explicit `CLONE_NEWUSER` with UID/GID mapping |
| Mount namespace | Always (bubblewrap requires it) | Always when FS restrictions are active |
| Seccomp | BPF filter blocking `AF_UNIX` socket creation (applied via custom binary after socat starts) | None |

Both create PID namespaces. curb mounts a fresh `/proc` when a mount namespace
is active (default when FS restrictions are on), so the sandboxed process only
sees its own PIDs.
Cross-namespace signal delivery is restricted by user namespace UID boundaries
(only same-UID processes can be signaled).

**srt advantage**: seccomp BPF provides an additional layer of defense by
blocking `AF_UNIX` socket creation, preventing the sandboxed process from
communicating with host services via Unix sockets. In curb, Landlock covers
this indirectly (the child cannot access socket files unless they are in an
allowed path), but seccomp enforces it at the syscall level regardless of
filesystem policy.

## Environment

|  | srt | curb |
|---|---|---|
| Model | Full host environment inherited, proxy vars added | Deny-by-default: only listed vars passed |
| Passthrough | Implicit | `--env` flag with glob patterns; `--env '*'` for full passthrough |

## Dependencies

| srt | curb |
|---|---|
| Node.js runtime | None |
| bubblewrap | (kernel syscalls) |
| ripgrep | (kernel syscalls) |
| socat | (kernel syscalls) |
| Custom `apply-seccomp` binary | (kernel syscalls) |

curb has no external runtime dependencies on Linux. Network filtering uses
gvisor's netstack, which is compiled in.

## Boot sequence

srt starts bubblewrap (which creates namespaces and sets up bind mounts),
launches socat inside the sandbox to bridge proxy sockets, applies a seccomp
filter via a custom binary, and then runs the user command. This multi-stage
sequence involves several process spawns and the Node.js runtime.

curb re-execs itself into a new user namespace via a single `clone()` call.
The child sets up Landlock rules, optionally creates a TAP device for
networking, and runs the command. No intermediate processes are spawned.

## Performance

Benchmarks run via `make bench` (see `bench/bench_linux_test.go`). These
measure end-to-end time including sandbox setup, command execution, and
teardown. curb is benchmarked in both proxy mode (default) and TUN mode.

| Benchmark | curb (proxy) | curb (TUN) | srt | Proxy vs srt |
|---|---|---|---|---|
| Boot (`true`) | ~40 ms | - | ~212 ms | 5.3x |
| HTTP single request | ~43 ms | ~65 ms | ~226 ms | 5.3x |
| HTTP batch (10 requests) | ~89 ms | ~113 ms | ~291 ms | 3.3x |

The boot benchmark runs `/usr/bin/true` inside the sandbox, isolating
setup/teardown overhead. The HTTP benchmarks run `curl` against a local HTTP
server with domain filtering enabled.

The batch benchmark makes 10 requests within a single sandbox invocation,
so boot cost is paid once. Subtracting boot time gives per-request network
overhead:

- curb (proxy): ~4.9 ms/request
- curb (TUN): ~7.3 ms/request
- srt: ~7.9 ms/request

Boot is the dominant difference (5x). Proxy mode is the fastest network path
because it avoids the userspace TCP/IP stack. TUN mode adds ~50% overhead
per request for the defense-in-depth filtering layer. For long-running
processes that make many requests, the startup cost matters less and overall
performance converges.

## Summary

The projects make different architectural choices that lead to different
tradeoffs:

- **Filesystem**: allow-only (curb) vs deny-only (srt). Stricter by default
  vs easier to configure for broad compatibility.
- **Network**: both use HTTP proxies for domain filtering by default. curb's
  MITM proxy terminates TLS, making filtering immune to ECH. curb can
  optionally add transparent packet-level filtering (`--tun always`) for
  non-HTTP programs. srt uses SOCKS5 for non-HTTP TCP.
- **Non-proxy programs**: in both tools, programs ignoring proxy env vars get
  no network (empty namespace). curb's `--tun always` mode is the exception,
  providing domain-filtered access for all programs.
- **Dependencies**: curb uses kernel interfaces directly with no runtime
  dependencies. srt depends on bubblewrap, socat, ripgrep, and Node.js.
