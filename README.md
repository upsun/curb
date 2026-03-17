# curb

Unprivileged process sandboxing for Linux.

curb runs a command inside a sandbox with filesystem restrictions, domain-level network filtering, executable control, and environment sanitization -- all without root privileges. It uses Linux user namespaces, Landlock LSM, mount namespaces, and a userspace TCP/IP stack (gvisor netstack).

On non-Linux platforms, curb applies environment sanitization only and warns about unavailable restrictions.

## Installation

```
go install github.com/upsun/curb@latest
```

Requires Go 1.26+ and Linux kernel 3.8+ (user namespaces). Landlock (kernel 5.13+) provides additional hardening when available. Network filtering requires kernel 4.18+ (user + network namespaces). The default proxy mode needs only network namespaces; the optional TUN/TAP hardening layer also requires `/dev/net/tun`.

## Quick Start

Start an interactive shell inside the sandbox (uses `$SHELL`, falling back to `/bin/sh`):

```
curb
```

Run a command with default restrictions (filesystem read-only, no network, sanitized environment):

```
curb make check
```

Allow HTTPS access to specific domains:

```
curb --domains 'example.com,*.github.com' -- curl https://example.com
```

Allow a build tool to write to the current directory and access specific domains:

```
curb --write . --domains 'registry.npmjs.org,*.npmjs.org' -- npm install
```

Forward localhost services from the host:

```
curb --domains localhost -- curl http://127.0.0.1:8080/
```

Dry run to inspect the sandbox plan:

```
curb --dry-run make test
```

## CLI Reference

### Network

| Flag | Env Var | Description |
|------|---------|-------------|
| `--domains` | `CURB_DOMAINS` | Allowed domain patterns (comma-separated). Bare domains match exactly; use `*.example.com` for subdomains, `*` to allow all, `localhost` for localhost forwarding. |
| `--ips` | `CURB_IPS` | Allowed IP addresses or CIDR ranges (e.g. `10.0.0.1`, `192.168.0.0/16`, `::1`). |
| `--proxy` | `CURB_PROXY` | MITM proxy for HTTP/HTTPS filtering: `on` (default), `off`. The proxy terminates TLS, making domain filtering immune to ECH. |
| `--tun` | `CURB_TUN` | TUN/TAP netstack layer: `auto` (default), `always`. With `auto`, TUN is used only when `--proxy off`. With `always`, TUN provides defense-in-depth alongside the proxy. |
| `--unrestricted-net` | `CURB_UNRESTRICTED_NET` | Allow unrestricted network access (no filtering). Cannot combine with `--domains` or `--ips`. |
| `--allow-http` | `CURB_ALLOW_HTTP` | Allow plaintext HTTP (port 80) when domain filtering is active |
| `--ech` | `CURB_ECH` | ECH handling mode: `strip` (default, strips ECH from DNS), `allow`, `deny` (TUN mode only) |
| `--allow-no-sni` | `CURB_ALLOW_NO_SNI` | Allow TLS connections without SNI (reduces filtering, TUN mode only) |

### Filesystem

| Flag | Env Var | Description |
|------|---------|-------------|
| `--read` | `CURB_READ` | Readable paths (`!` prefix denies access, `!*` clears all defaults) |
| `--write` | `CURB_WRITE` | Writable paths (`!` prefix makes read-only, `'*'` disables FS restrictions) |

By default, system paths (`/usr`, `/lib`, `/proc`), specific `/etc` files (DNS, TLS certs, timezone, passwd), device nodes (`/dev/null`, `/dev/urandom`, `/dev/pts`), and the current directory are accessible. Sensitive files like `/etc/machine-id` and `/etc/hostname` are not exposed. A private temp directory is created and set as `TMPDIR`. Use `--write .` to grant write access to the current directory. Glob patterns are supported (e.g. `--read '~/docs/*.md'`).

Use `!` to deny access to specific paths. When the denied path is under an allowed parent, it is actively blocked via overmount (empty tmpfs for directories, `/dev/null` for files). Examples: `--read /etc --read '!/etc/shadow'` hides `/etc/shadow`. `--write /data --write '!/data/config'` makes `/data/config` read-only. `--exec '!/usr/bin/curl'` blocks executing curl. Use `--read '!*'` to clear all default read paths.

### Executable Control

| Flag | Env Var | Description |
|------|---------|-------------|
| `--exec` | `CURB_EXEC` | Allowed executables (`!` prefix removes defaults, `'*'` allows all) |

By default, only system binaries in `/usr/bin`, `/bin`, etc. and the target command itself have execute permission (via `MS_NOEXEC` mount flags and Landlock). Writable directories (TMPDIR) are not executable.

### Environment

| Flag | Env Var | Description |
|------|---------|-------------|
| `--env` | `CURB_ENV` | Pass through (`NAME`) or set (`NAME=VALUE`) env vars (`!` prefix removes defaults, `'*'` for all) |

By default, the environment is deny-by-default: only `HOME`, `PATH`, `TMPDIR`, `TERM`, `TZ`, `LANG`, and a few other safe variables are passed through. `SHELL` is passed through from the host. `PS1` is set to show a `(curb)` prefix (respects `NO_COLOR`). Secrets (`*_KEY`, `*_TOKEN`, `*_SECRET`, etc.) are blocked. Use `--env '!USER'` to remove USER from defaults, or `--env '!*'` to clear all default env vars.

### Output

| Flag | Env Var | Description |
|------|---------|-------------|
| `--log-file` | `CURB_LOG_FILE` | Write structured JSON logs to file |
| `-v`, `--verbose` | `CURB_VERBOSE` | Print filtering decisions to stderr |
| `-q`, `--quiet` | `CURB_QUIET` | Suppress warnings |

### Other

| Flag | Env Var | Description |
|------|---------|-------------|
| `-c`, `--config-file` | `CURB_CONFIG_FILE` | Config file path(s) (default: auto-discover `.curb.yaml`) |
| `-p`, `--profiles` | `CURB_PROFILES` | Activate named profiles (comma-separated, e.g. `node,git`) |
| `--dry-run` | | Print the sandbox plan without running the command |
| `--home` | | Set HOME environment variable for the sandboxed process |

## Profiles

Profiles are named, reusable config bundles for common toolchains. They contain only additive allowlist fields (domains, paths, exec, env) — no scalar settings.

```
curb --profiles node,git -- npm install
```

Built-in profiles: `node`, `python`, `php`, `go`, `rust`, `git`, `github`, `docker`, `claude-code`.

Profiles can also be activated via config file (`profiles: [node, git]` in `.curb.yaml`) or environment (`CURB_PROFILES=node,git`).

Profile search order (first match wins):
1. User: `$XDG_CONFIG_HOME/curb/profiles/<name>.yaml` (default `~/.config/curb/profiles/`)
2. System: `/etc/curb/profiles/<name>.yaml`
3. Built-in (embedded in binary)

Merge order: profiles (lowest) -> config file -> CLI flags -> env vars (highest). CLI `!` exclusions can remove anything added by profiles.

Manage profiles:
```
curb profile list          # list available profiles with source
curb profile show node     # print profile YAML to stdout
```

## Platform Support

| Platform | Restrictions | Notes |
|----------|-------------|-------|
| Linux (kernel 5.13+, mount ops) | Full | pivot_root + Landlock + MITM proxy (+ netstack with `--tun always`) |
| Linux (kernel 5.13+, no mount ops) | Strong | Landlock + MITM proxy; blocked paths return EACCES not ENOENT |
| Linux (kernel 4.18+, net NS only) | Network + env | MITM proxy for domain filtering; no FS restrictions (use `--write '*' --exec '*'`) |
| Linux (kernel 3.8-5.12, mount ops) | Strong | pivot_root + MITM proxy (no Landlock hardening) |
| macOS / Windows | Environment only | Sanitized env; all other restrictions unavailable |

## Troubleshooting

See [docs/troubleshooting.md](docs/troubleshooting.md) for solutions to common issues including user namespace restrictions, missing `/dev/net/tun`, and AppArmor on Ubuntu 24.04+.

## How It Works

1. **Environment sanitization**: deny-by-default environment with only safe variables passed through.
2. **User namespace**: the child runs as uid 0 in an isolated namespace (no host privileges).
3. **Mount namespace + pivot_root** (primary FS enforcement): a new root is built from bind-mounted allowed paths. Unmounted paths don't exist (ENOENT). `MS_RDONLY` and `MS_NOEXEC` enforce read-only and no-exec. `!` denials are enforced via overmount (empty tmpfs/`/dev/null` for read denials, `MS_RDONLY` for write denials, `MS_NOEXEC` for exec denials).
4. **Landlock LSM**: when both are available, Landlock is layered on top of pivot_root for defense-in-depth. On systems where mount operations are blocked (e.g. AppArmor), Landlock provides FS enforcement on its own (default-deny via EACCES). The only limitation without mount namespaces is that sub-path denials (`!` exclusions under an allowed parent) cannot be enforced.
5. **Network namespace + MITM proxy** (primary network enforcement): child gets an isolated network namespace with only loopback. An ephemeral CA and MITM proxy in the parent process filter HTTP/HTTPS by domain. Programs using `HTTPS_PROXY` get filtered access; programs ignoring it get no network. The proxy terminates TLS, making domain filtering immune to Encrypted Client Hello (ECH).
6. **TUN/TAP + netstack** (optional hardening, `--tun always`): a userspace TCP/IP stack provides defense-in-depth alongside the proxy. DNS queries, TLS SNI, and HTTP Host headers are filtered. Non-HTTP programs get domain-filtered network instead of a hard block.
