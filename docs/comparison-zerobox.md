# Comparison: curb vs zerobox

This document compares curb with
[zerobox](https://github.com/afshinm/zerobox), a process sandboxing CLI
and TypeScript SDK. zerobox vendors sandboxing crates from OpenAI's
[codex-rs](https://github.com/openai/codex) and adds a CLI, secret
injection, and filesystem snapshots on top.

Both tools sandbox a subprocess with filesystem, network, and environment
restrictions. curb is a single Go binary with no dependencies; zerobox is
a Rust binary that bundles vendored Codex crates (including bubblewrap
integration, Landlock, seccomp, and an HTTP proxy). On macOS, both use
Apple's Seatbelt.

## Filesystem

**zerobox** allows full disk read by default. Writes and network are
blocked. `--allow-read=<paths>` switches to a restricted read mode where
only minimal system paths and listed paths are readable. `--allow-write=
<paths>` grants write access to specific directories. `--deny-read` and
`--deny-write` override allows.

**curb** starts with nothing accessible. Only listed paths exist inside
the sandbox (ENOENT with mount NS, EACCES with Landlock-only). Read,
write, and execute permissions are controlled independently via `--read`,
`--write`, and `--exec`. Built-in profiles reduce configuration burden
for common toolchains.

zerobox's default-read posture is lower-friction: programs can read
configuration, caches, and tool state without explicit allowlisting. The
tradeoff is weaker confidentiality -- the process can read SSH keys, API
tokens, and browser data unless explicitly denied. curb's allowlist is
stricter but requires the caller to know what the sandboxed program
needs.

### Executable control

**zerobox** does not expose executable control as a CLI flag. Execution
restrictions are handled internally by the Codex upstream crates.

**curb** uses default-deny execution. Only the invoked command binary
(auto-added), dynamic linker directories, and profile/flag additions are
executable. The `--exec` flag grants execute permission on additional
paths.

### Persistent state and snapshots

**zerobox** includes a filesystem snapshot system (`--snapshot`,
`--restore`). It records changes during execution using BLAKE3 content
hashing and Merkle trees, then can automatically revert them after the
command exits. Session management commands (`zerobox snapshot
list/diff/restore/clean`) allow inspection and manual restoration.

**curb** is stateless. Each invocation starts fresh. Persistence is left
to the caller (e.g. writing to a granted writable directory).

zerobox's snapshot/restore is useful for trial runs and reversible agent
workflows. It operates at the application level (tracking file changes),
not at the kernel level (no overlayfs).

## Network

Both tools use an HTTP proxy for domain filtering. The sandboxed process
gets proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`) that
route traffic through the filtering proxy in the parent. Programs that
ignore proxy env vars get no network (isolated via namespace on Linux,
Seatbelt on macOS).

**zerobox** uses the Codex `codex-network-proxy` crate. When secrets are
configured (see below), the proxy runs in MITM mode -- it terminates TLS
to inspect and modify HTTP headers, injecting a CA certificate into the
child environment (`CURL_CA_BUNDLE`, `SSL_CERT_FILE`,
`NODE_EXTRA_CA_CERTS`, etc.). Without secrets, the proxy behavior is not
documented as clearly, but the Codex upstream uses CONNECT passthrough
for HTTPS in standard mode. There is no SOCKS5 proxy -- non-HTTP TCP
(SSH, git protocol, database connections) is blocked entirely when
network filtering is active.

**curb** runs both an HTTP proxy and a SOCKS5 proxy. HTTPS uses CONNECT
passthrough by default: the proxy checks the hostname from the CONNECT
request, then tunnels the encrypted stream without terminating TLS. The
opt-in `--inject-header` (see below) terminates TLS for a
named host only, to inject a credential; every other host stays passthrough.
The SOCKS5 proxy handles non-HTTP TCP (e.g. SSH via `ProxyCommand`).
Both filter on the CONNECT hostname or SOCKS5 destination, not on TLS
SNI, so neither is affected by Encrypted Client Hello (ECH). curb
supports IP address and CIDR range filtering via `--ips`. curb supports
forwarding localhost traffic to the host via `--host-loopback`.

The MITM requirement for zerobox's secret injection is a significant
tradeoff: it breaks certificate pinning, requires injecting a custom CA
into every TLS-using tool, and means the proxy can see all HTTPS
content. curb avoids TLS termination by default, and confines it to the
specific hosts named in `--inject-header` when injection is used — every
other host still tunnels untouched.

The lack of SOCKS5 in zerobox means non-HTTP TCP protocols (SSH, git://,
database connections) cannot be domain-filtered -- they are either fully
blocked (with `--allow-net=<domains>`) or fully open (with bare
`--allow-net`).

## Secret injection

This is zerobox's primary differentiator.

**zerobox** `--secret OPENAI_API_KEY=sk-proj-123` passes a credential to
the sandbox. The sandboxed process sees a random placeholder
(`ZEROBOX_SECRET_<64 hex chars>`) in the environment variable, not the
real value. `--secret-host OPENAI_API_KEY=api.openai.com` restricts the
secret to a specific domain. The MITM proxy intercepts HTTPS requests,
scans them for placeholder tokens, and substitutes the real secret value
only for approved hosts. The placeholder is 32 random bytes so it is long
and unique enough not to collide with legitimate request content during
that scan.

**curb** has opt-in credential injection via `--inject-header ENV_VAR=HOST`
(Linux only). The two tools' mechanisms have converged: the sandbox sees only a
placeholder in `ENV_VAR`, never the real value; the proxy terminates TLS for
`HOST` (presenting a per-run CA the sandbox trusts) and substitutes the
placeholder with the real value wherever the client put it among the request
headers. Like zerobox, it is header-agnostic — `Authorization: Bearer`,
`x-api-key`, or any other header all work, with no auth-scheme knowledge
configured. Without the flag, curb performs no injection and no TLS termination;
secrets otherwise reach the process only via `--env`.

The substantive difference is blast radius. zerobox flips its proxy into MITM
mode for *all* allowed HTTPS once any secret is configured (`config.network.mitm`
is global); curb terminates TLS only for the hosts named in `--inject-header` and
leaves every other host on untouched passthrough. The two designs are otherwise
close: both are header-only (zerobox's `substitute_headers` and curb's
`replaceInHeaders` both scan header values, not request bodies), both bind a
secret to approved hosts, and both let the program choose which header carries
the marker.

Two smaller differences. First, zerobox's placeholder is 32 random bytes (unique
per run) to avoid colliding with real content during the scan; curb uses a
stable, distinctive per-variable sentinel, which keeps it collision-safe while
letting a tool that approves a custom credential (e.g. Claude Code) approve it
once rather than every run. Both placeholders carry no secret weight — neither is
the credential. Second, zerobox couples the secret to an env var name
(`--secret KEY=VALUE`) and the host separately (`--secret-host KEY=hosts`); curb's
single `ENV_VAR=HOST` does both — the env var both reads the real value on the
host and carries the placeholder in the sandbox.
Both put the variable first, leaving room for a credential to name several hosts.

Both approaches prevent a compromised or malicious process from reading the
real secret and exfiltrating it. The shared cost is TLS termination and CA
trust — for curb, only on the injected hosts.

## Process isolation

Both tools use user namespaces, PID namespaces, and mount namespaces on
Linux.

**zerobox** delegates namespace creation to bubblewrap (bwrap) via the
Codex `codex-linux-sandbox` crate. The zerobox binary uses argv[0]
dispatch: when invoked as `codex-linux-sandbox`, it runs the sandbox
helper instead of the CLI. Seccomp filters come from the Codex
`codex-process-hardening` crate.

**curb** creates namespaces directly via `clone()` syscalls and uses a
re-exec architecture (parent clones itself, child initializes enforcement
and execs the target). Seccomp BPF for AF_UNIX blocking is built in Go
(10 instructions, zero heap allocation). Signal forwarding handles
SIGINT/SIGTERM/SIGHUP with escalation on repeated signals.

### Landlock

Both tools use Landlock as a fallback when full namespace support is
unavailable.

**zerobox** (via Codex) uses Landlock-only mode when user namespaces are
blocked (e.g. Docker without `--cap-add SYS_ADMIN`). In this mode,
custom file policies (`--allow-read`, etc.) are not supported -- only
default deny-write and deny-network apply. `--strict-sandbox` makes this
an error instead of a degraded sandbox.

**curb** uses Landlock as a defense-in-depth layer on top of mount
namespace enforcement, and as a capable standalone alternative when mount
NS is unavailable. Landlock-only mode supports full read/write/exec
policies but cannot enforce sub-path denials (`!` exclusions under an
allowed parent).

## Environment

**zerobox** inherits only `PATH`, `HOME`, `USER`, `SHELL`, `TERM`, and
`LANG` by default. `--allow-env` (bare) inherits all; `--allow-env=
K1,K2` inherits specific keys. `--deny-env=K1,K2` blocks keys (takes
precedence). `--env KEY=VALUE` sets explicit variables.

**curb** inherits a similar small set of safe variables by default.
`--env NAME` passes through a host variable; `--env NAME=VALUE` sets one
explicitly. `--env '*'` passes the full host environment.

Both tools take a deny-by-default approach to environment variables,
which is stricter than tools like srt or jai.

## Configuration

**zerobox** has no configuration file or profile system. All settings are
passed via CLI flags per invocation. There is no equivalent of curb's
auto-discovered config files or composable profiles.

**curb** uses YAML config files (`.curb.yaml`, auto-discovered by
walking up from the working directory) and composable profiles. 11
built-in profiles cover common toolchains. Profiles can include other
profiles. Config layers merge in priority order: profiles -> config
file -> environment variables -> CLI flags.

For repeated use with the same toolchain, curb's profiles significantly
reduce command-line verbosity. zerobox requires the full set of flags
each time (or wrapper scripts).

## SDK

**zerobox** ships a TypeScript SDK (`zerobox` on npm) with typed options
and template-literal syntax for shell and JS commands. Each command
spawns a fresh sandbox process.

**curb** has no SDK. It is a CLI tool invoked directly or via config
files.

## Platform support

| | zerobox | curb |
|---|---|---|
| Linux (bwrap available) | Full (bwrap + seccomp) | Full (mount NS + Landlock + seccomp) |
| Linux (no user NS) | Degraded (Landlock-only, limited policies) | Degraded (Landlock-only, full policies) |
| macOS | Seatbelt (via Codex) | Seatbelt (native) |
| Windows | Planned (not yet functional) | Environment sanitization only |

## Dependencies

| zerobox | curb |
|---|---|
| Vendored Codex crates (Rust, compiled in) | None |
| bubblewrap (runtime, Linux) | (kernel syscalls) |
| rustls (compiled in) | (kernel syscalls) |
| tokio async runtime (compiled in) | (kernel syscalls) |

zerobox is a single binary but depends on bubblewrap at runtime on
Linux. curb has no external runtime dependencies.

## Summary table

| Aspect | zerobox | curb |
|---|---|---|
| Default FS read | Full disk | Curated defaults (allowlist) |
| Default FS write | Blocked | Blocked |
| Default network | Blocked | Blocked |
| FS enforcement | bwrap (mount NS) + Landlock fallback | pivot_root (mount NS) + Landlock layered |
| Network filtering | HTTP proxy (MITM when secrets active) | HTTP + SOCKS5 proxy (CONNECT passthrough; per-host TLS termination only with `--inject-header`) |
| Secret injection | Yes (MITM all HTTPS, placeholder substitution) | Yes (`--inject-header`, placeholder substitution, TLS terminated per host, Linux) |
| Snapshot/restore | Yes (BLAKE3 + Merkle tree) | No (stateless) |
| IP/CIDR filtering | No | Yes (`--ips`) |
| SOCKS5 (non-HTTP TCP) | No | Yes |
| Host-loopback forwarding | No | Yes (`--host-loopback`) |
| Executable control | Not exposed as CLI flag | Default-deny with `--exec` |
| Sub-path denials | Via bwrap/Seatbelt deny rules | Via overmount (mount NS) or Seatbelt deny |
| Environment | Deny-by-default | Deny-by-default |
| Configuration | CLI flags only | YAML + composable profiles |
| SDK | TypeScript/npm | No |
| Platforms | Linux, macOS (Windows planned) | Linux, macOS, Windows (limited) |
| Language | Rust | Go |
| Runtime dependencies | bubblewrap (Linux) | None |
| Upstream | Vendored OpenAI Codex `codex-rs` | Standalone |

## Ideas for curb

Features or approaches from zerobox worth considering for curb.

### Secret injection

zerobox's placeholder-and-substitute model prevents the sandboxed
process from ever seeing real credentials. This is valuable for AI agent
use cases where the agent needs to call authenticated APIs but should not
be able to read or exfiltrate the actual tokens.

curb now implements the same model: `--inject-header ENV_VAR=HOST` sets the
sandbox's copy of the variable to a placeholder and has the proxy substitute the
real value in request headers, header-agnostically. Unlike zerobox, TLS
termination is confined to the named hosts rather than applied to all allowed
HTTPS while secrets are active. Possible future work: reading the token from an
inherited fd so it touches neither argv nor the environment.

A lighter-weight, complementary option: support secret-aware environment
variables that are populated only at exec time and excluded from
`/proc/<pid>/environ` (e.g. via a helper that reads from a pipe). This
would prevent environment enumeration but not prevent the process from
reading its own memory.

### Filesystem snapshots

zerobox's snapshot/restore system is useful for trial runs and
reversible workflows. curb could implement this at the application level
(tracking file changes via inotify or periodic scanning) without
requiring overlayfs. However, this adds complexity and curb's stateless
model is simpler. For users who need reversibility, overlay mode (see
jai comparison) would provide kernel-level isolation that is harder to
bypass than application-level tracking.

### TypeScript SDK

A programmatic SDK would make curb easier to integrate into agent
frameworks. This is a distribution concern rather than a sandboxing
feature. If curb adds an SDK, it should be thin (spawn the binary,
parse output) rather than reimplementing sandbox logic.
