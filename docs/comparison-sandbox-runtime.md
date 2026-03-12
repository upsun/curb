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
- curb's network filtering is transparent — programs do not need proxy
  support. srt requires programs to respect `HTTP_PROXY` / `ALL_PROXY`
  environment variables; programs that ignore them get no network.
- curb has no external dependencies (no bubblewrap, socat, ripgrep, or
  Node.js runtime to install).
- srt isolates the PID namespace, so the sandboxed process cannot see or
  signal host processes. curb does not, but its user namespace means the
  child has no capabilities in the host namespace, limiting what it can do
  with host PIDs. srt's PID namespace requires `CLONE_NEWPID`, which may
  not be available in nested or restricted environments (srt can be configured
  with a weaker sandbox mode in this case).
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

|  | srt | curb |
|---|---|---|
| Mechanism | `bwrap --unshare-net`, then HTTP + SOCKS5 proxies exposed as Unix sockets, bridged in via socat | User namespace + network namespace + TAP device + userspace TCP/IP stack (gvisor netstack) |
| Traffic routing | Via `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` env vars | Transparent: the TAP is the child's only network interface |
| Program compatibility | Only programs that respect proxy env vars | All programs |
| Protocol coverage | HTTP via HTTP proxy, other TCP via SOCKS5 | All IP traffic (full TCP/IP stack) |
| Filtering signal | Proxy protocol: CONNECT hostname / SOCKS5 destination | DNS responses, TLS SNI, HTTP Host header |
| ECH handling | Not applicable (filtering happens before TLS) | Can strip, allow, or deny Encrypted Client Hello |
| Localhost forwarding | No | `--domains localhost` forwards loopback traffic to host |

**srt advantage**: srt filters at the proxy protocol level, so it knows the
destination hostname from the explicit CONNECT or SOCKS5 request without
inspecting TLS. curb infers the hostname from packet contents (DNS, SNI,
Host header) and must handle evasion techniques (ECH, missing SNI, SNI
spoofing) explicitly — though it does so successfully in testing
(see `docs/test-reports/`).

**srt advantage**: programs that ignore proxy env vars get zero network access
(there is no network interface). This is a hard block with no bypass path,
though it also means legitimate programs that do not support proxies will fail.

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
teardown.

| Benchmark | curb | srt | Ratio |
|---|---|---|---|
| Boot (`true`) | ~35 ms | ~208 ms | 6x |
| HTTP single request | ~61 ms | ~251 ms | 4x |
| HTTP batch (10 requests) | ~111 ms | ~315 ms | 2.8x |

The boot benchmark runs `/usr/bin/true` inside the sandbox, isolating
setup/teardown overhead. The HTTP benchmarks run `curl` against a local HTTP
server with domain filtering enabled.

The batch benchmark makes 10 requests within a single sandbox invocation,
so boot cost is paid once. Subtracting boot time gives per-request network
overhead:

- curb: ~7.6 ms/request
- srt: ~10.7 ms/request

Boot is the dominant difference (6x). Per-request network overhead is in the
same ballpark — curb's netstack path is roughly 30% faster than srt's proxy
path. For long-running processes that make many requests, the startup cost matters
less and overall performance converges.

## Summary

The projects make different architectural choices that lead to different
tradeoffs:

- **Filesystem**: allow-only (curb) vs deny-only (srt). Stricter by default
  vs easier to configure for broad compatibility.
- **Network**: packet-level (curb) vs proxy-level (srt). Transparent to all
  programs vs simpler filtering logic.
- **Evasion surface**: srt avoids TLS-level evasion by design. curb handles
  these at the packet level (ECH stripping, SNI validation, missing-SNI
  rejection) and covers all protocols.
- **Dependencies**: curb uses kernel interfaces directly with no runtime
  dependencies. srt depends on bubblewrap, socat, ripgrep, and Node.js.
