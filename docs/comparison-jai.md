# Comparison: curb vs jai

This document compares curb with Stanford's
[jai](https://jai.scs.stanford.edu/) ("jailed AI"), a filesystem sandbox for
AI agents. The comparison covers Linux only (jai does not support other
platforms).

Both tools sandbox a subprocess to limit the damage from bugs, mistakes,
and overly broad file operations. They take fundamentally different
approaches: curb starts with nothing accessible and adds paths via an
allowlist; jai starts with the full filesystem readable and uses an
overlayfs copy-on-write layer to capture writes harmlessly.

jai is written in C++23 (~2,700 lines, autotools build) and requires
Linux 6.13+ for fd-based mount APIs (`fsopen`, `open_tree`, `move_mount`,
`mount_setattr`). curb is a single Go binary with no runtime dependencies,
supporting Linux 5.13+ with graceful degradation, macOS (Seatbelt), and
Windows (environment sanitization only).

## Filesystem

The tools have opposite default postures.

**jai** mounts the user's home directory as an overlayfs copy-on-write
layer (in casual mode). Reads pass through to the real filesystem; writes
land in a per-jail changes directory (`$HOME/.jai/<name>.changes`),
leaving originals untouched. The rest of the filesystem (`/usr`, `/lib`,
etc.) is mounted read-only via `mount_setattr(MOUNT_ATTR_RDONLY)`. `/tmp`
and `/var/tmp` are replaced with private tmpfs mounts. Granted directories
(`--dir`) get full read-write access. In strict and bare modes, the home
directory starts empty and only granted directories are accessible.

**curb** starts with nothing visible. Only listed paths exist inside the
sandbox (ENOENT with mount NS, EACCES with Landlock-only). Read, write,
and execute permissions are controlled independently via `--read`,
`--write`, and `--exec`. Built-in profiles reduce configuration burden for
common toolchains.

jai's overlay approach is lower-friction: agents can read configuration
files, caches, and tool state without explicit allowlisting. The tradeoff
is weaker confidentiality in casual mode -- the process can read SSH keys,
API tokens, and browser data. jai addresses this with file masking (overlay
whiteouts that hide specific paths like `.ssh` and `.gnupg`) and a strict
mode that runs as a separate system user.

curb's allowlist is stricter by default but requires the caller to know
what paths the sandboxed program needs.

### Sub-path denials

Both tools support hiding specific paths under an otherwise-accessible
parent.

**jai** uses overlay whiteout files in casual mode. Once the overlay is
created, new masks require `jai -u` (unmount and recreate). In strict/bare
modes, hiding is implicit (home is empty).

**curb** uses tmpfs overmounts for directories and `/dev/null` binds for
files, controlled via the `!` prefix on path flags (`--read '!/path'`).
This requires mount namespace support; Landlock-only mode cannot enforce
sub-path denials.

### Persistent state

**jai** persists overlay changes across invocations. Named jails
(`-j name`) each get their own overlay, so state from previous runs is
visible in subsequent ones. `jai -u` unmounts and optionally cleans up.

**curb** is stateless. Each invocation starts fresh. Persistence is left
to the caller (e.g. writing to a granted directory).

## Network

**jai** does not restrict network access. Jailed processes can make
arbitrary connections, exfiltrate data, and call external APIs. The jai
security page states this explicitly and recommends containers or VMs when
network isolation is needed.

**curb** runs an HTTP proxy and a SOCKS5 proxy for domain filtering,
with the sandboxed process in an isolated network namespace (loopback
only). `--domains` controls allowed hostnames; `--ips` controls allowed
IP addresses and CIDR ranges. Programs that ignore proxy environment
variables get no network. `--unrestricted-net` disables network filtering
while keeping filesystem restrictions.

This is the largest functional gap between the two tools.

## Process isolation

Both tools use PID namespaces (`CLONE_NEWPID`) so jailed processes cannot
signal or ptrace external processes.

**jai** additionally creates an IPC namespace (`CLONE_NEWIPC`), isolating
System V shared memory, semaphores, and message queues. curb does not
create an IPC namespace.

**jai** uses a two-fork architecture (parent -> PID 1 -> PID 2) to
preserve full job control (SIGSTOP/SIGCONT propagation) across the
namespace boundary.

**curb** uses a re-exec architecture (parent clones itself into the
namespace, child initializes enforcement and execs the target). Signal
forwarding handles SIGINT/SIGTERM/SIGHUP with escalation on repeated
signals.

**curb** additionally uses seccomp BPF to block AF_UNIX socket creation,
preventing communication with host services via Unix domain sockets. jai
hides `/run/user/$UID` (which contains most user session sockets) but does
not filter socket syscalls.

### Credential isolation

**jai** strict mode runs the jailed process as an unprivileged system user
(`jai`), providing kernel-enforced confidentiality: the process cannot read
files accessible only to the invoking user's UID. Granted directories use
id-mapped mounts to present the correct ownership.

**curb** runs the child as uid 0 inside a user namespace (mapped to the
invoking user outside). File access checks use the real UID. curb relies
on mount namespace isolation (paths not mounted are not accessible) rather
than UID-based confidentiality.

## Environment

**jai** inherits the host environment and filters out variables matching
secret-like patterns (`*_TOKEN`, `*_PASSWORD`, `*_SECRET_KEY`,
`*_CREDENTIAL`, `DATABASE_URL`, `KUBECONFIG`, etc.). Additional patterns
can be added via `--unsetenv`. Variables can be re-exposed via `--setenv`.

**curb** uses a deny-by-default model. Only a small set of safe variables
(`PATH`, `TERM`, `LANG`, `TZ`, `HOME`, etc.) is passed through. Additional
variables are added with `--env NAME` or `--env NAME=VALUE`. `--env '*'`
passes the full host environment (with no pattern-based filtering).

jai's pattern filtering is a pragmatic middle ground: it allows most
environment variables through while catching common secret patterns. curb's
deny-by-default is stricter but requires explicit opt-in for each variable.

## Configuration

**jai** uses INI-like config files stored in `$HOME/.jai/`. There is a
`.defaults` file (auto-generated), a `default.conf` for the default jail,
per-jail `.jail` files, and per-command `.conf` files (e.g. `python.conf`
is loaded automatically when running `jai python`). Config supports
variable substitution (`${HOME}`) and include directives.

**curb** uses YAML config files (`.curb.yaml`, auto-discovered by walking
up from the working directory) and composable profiles. 11 built-in
profiles cover common toolchains. Profiles can include other profiles.
Config layers merge in priority order: profiles -> config file ->
environment variables -> CLI flags.

jai's per-command auto-configuration (loading `CMD.conf` based on the
command name) reduces friction for repeated use. curb requires explicit
profile activation (`-p python`).

## Platform support

| | jai | curb |
|---|---|---|
| Linux 6.13+ | Full | Full |
| Linux 5.13–6.12 | Not supported | Full (Landlock + mount NS) |
| Linux 3.8–5.12 | Not supported | mount NS + proxy (no Landlock) |
| macOS | Not supported | Seatbelt + proxy |
| Windows | Not supported | Environment sanitization only |
| NFS home directories | Bare mode only (no overlay, no id-mapped mounts) | Full (no kernel FS dependencies) |

jai's reliance on fd-based mount APIs limits it to recent kernels. curb
probes available capabilities at startup and degrades gracefully, logging
warnings about reduced isolation.

## Summary table

| Aspect | jai | curb |
|---|---|---|
| Default posture | Default-allow (overlay captures writes) | Default-deny (allowlist) |
| Filesystem enforcement | overlayfs + mount_setattr | pivot_root + Landlock + mount options |
| Network filtering | None | HTTP + SOCKS5 proxy, domain/IP filtering |
| PID isolation | Yes (two-fork, full job control) | Yes (re-exec, signal escalation) |
| IPC isolation | Yes (`CLONE_NEWIPC`) | No |
| seccomp | No | AF_UNIX blocking |
| Credential isolation | Strict mode (separate UID) | Mount NS (paths not mounted = not accessible) |
| Environment | Pattern-based secret removal | Deny-by-default |
| Executable control | No | Landlock EXECUTE right |
| Configuration | Per-command/per-jail config files | YAML + composable profiles |
| Persistent state | Overlay changes survive across runs | Stateless |
| Platforms | Linux 6.13+ | Linux 5.13+, macOS, Windows (limited) |
| Language | C++23 | Go |
| Dependencies | C++ runtime, autotools build | None (single static binary) |

## Ideas for curb

Features or approaches from jai worth considering for curb.

### IPC namespace

jai creates an IPC namespace (`CLONE_NEWIPC`) to isolate System V shared
memory, semaphores, and message queues. Adding `CLONE_NEWIPC` to curb's
`clone` flags is low-cost and closes a minor isolation gap. System V IPC
is rarely used by modern programs but is a valid cross-process
communication channel that curb currently leaves open.

### Environment deny-patterns

When curb users opt into `--env '*'` (pass all host variables), they lose
all environment filtering. jai's pattern-based approach (`*_TOKEN`,
`*_PASSWORD`, etc.) would be useful as a safety net in this case: even with
full passthrough, known secret patterns would be stripped unless explicitly
re-added. This could be a `--env-deny-patterns` flag or a default behavior
when `--env '*'` is used.

### Auto-profile matching

jai automatically loads `CMD.conf` when the command name matches a config
file. curb could do something similar: when the sandboxed command is
`python`, `node`, `go`, etc., suggest or auto-activate the matching
built-in profile. This reduces friction for the common case where users
run `curb python ...` without remembering to add `-p python`.

### Overlay / copy-on-write mode

jai's overlay model lets agents see the full home directory while writes
are captured harmlessly. This is a fundamentally different tradeoff from
curb's allowlist: lower security, much lower friction. An `--overlay`
mode could serve users who want broad read access with write capture
rather than strict allowlisting. This would require overlayfs support
(Linux only, not available on NFS) and would weaken curb's default-deny
posture, so it would need to be opt-in with clear documentation of the
security implications.

### Named / persistent sandboxes

jai's named jails persist overlay state across invocations. This is useful
for long-running agent workflows where an agent needs to resume work
across multiple sessions. curb is currently stateless by design. If
overlay mode were added, persistent named sandboxes would be a natural
extension. Without overlay, persistence is already available via granted
writable directories.
