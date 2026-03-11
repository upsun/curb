# curb

Unprivileged process sandboxing for Linux.

curb runs a command inside a sandbox with filesystem restrictions, domain-level network filtering, executable control, and environment sanitization -- all without root privileges. It uses Linux user namespaces, Landlock LSM, mount namespaces, and a userspace TCP/IP stack (gvisor netstack).

On non-Linux platforms, curb applies environment sanitization only and warns about unavailable restrictions.

## Installation

```
go install github.com/upsun/curb@latest
```

Requires Go 1.26+ and Linux kernel 5.13+ (for Landlock). Network filtering requires kernel 4.18+ (user + network namespaces) and `/dev/net/tun`.

## Quick Start

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
| `--allow-http` | `CURB_ALLOW_HTTP` | Allow plaintext HTTP (port 80) when domain filtering is active |
| `--ech` | `CURB_ECH` | ECH handling mode: `strip` (default, strips ECH from DNS), `allow`, `deny` |
| `--allow-no-sni` | `CURB_ALLOW_NO_SNI` | Allow TLS connections without SNI (reduces filtering) |

### Filesystem

| Flag | Env Var | Description |
|------|---------|-------------|
| `--read` | `CURB_READ` | Readable paths (`!` prefix removes defaults, `!*` clears all) |
| `--write` | `CURB_WRITE` | Writable paths (`!` prefix removes defaults, `'*'` disables FS restrictions) |
| `--hide` | `CURB_HIDE` | Paths to hide (overmounted with empty tmpfs) |

By default, system paths (`/usr`, `/lib`, `/proc`), specific `/etc` files (DNS, TLS certs, timezone, passwd), device nodes (`/dev/null`, `/dev/urandom`, `/dev/pts`), and the current directory are accessible. Sensitive files like `/etc/machine-id` and `/etc/hostname` are not exposed. A private temp directory is created and set as `TMPDIR`. Use `--write .` to grant write access to the current directory. Use `--hide` to hide sensitive paths (e.g. `--hide ~/.ssh`). Glob patterns are supported (e.g. `--read '~/docs/*.md'`).

Use `!` to exclude specific defaults: `--read !/etc/passwd` removes `/etc/passwd` from the default readable files. Use `--read '!*'` to clear all default read paths. Use `--read /etc` to re-add the whole `/etc` directory.

### Executable Control

| Flag | Env Var | Description |
|------|---------|-------------|
| `--exec` | `CURB_EXEC` | Allowed executables (`!` prefix removes defaults, `'*'` allows all) |

By default, only system binaries in `/usr/bin`, `/bin`, etc. and the target command itself have execute permission (via Landlock). Writable directories (TMPDIR) are not executable.

### Environment

| Flag | Env Var | Description |
|------|---------|-------------|
| `--env` | `CURB_ENV` | Pass through (`NAME`) or set (`NAME=VALUE`) env vars (`!` prefix removes defaults, `'*'` for all) |

By default, the environment is deny-by-default: only `HOME`, `PATH`, `SHELL`, `TMPDIR`, `TERM`, `TZ`, `LANG`, and a few other safe variables are passed through. Secrets (`*_KEY`, `*_TOKEN`, `*_SECRET`, etc.) are blocked. Use `--env '!USER'` to remove USER from defaults, or `--env '!*'` to clear all default env vars.

### Output

| Flag | Env Var | Description |
|------|---------|-------------|
| `--log-file` | `CURB_LOG_FILE` | Write structured JSON logs to file |
| `-v`, `--verbose` | `CURB_VERBOSE` | Print filtering decisions to stderr |
| `-q`, `--quiet` | `CURB_QUIET` | Suppress warnings |

### Other

| Flag | Description |
|------|-------------|
| `--dry-run` | Print the sandbox plan without running the command |
| `--home` | Set HOME environment variable for the sandboxed process |

## Platform Support

| Platform | Restrictions | Notes |
|----------|-------------|-------|
| Linux (kernel 5.13+) | Full | Landlock + namespaces + netstack |
| Linux (kernel 4.18-5.12) | Degraded | No Landlock; mount/seccomp only |
| macOS / Windows | Environment only | Sanitized env; all other restrictions unavailable |

## Troubleshooting

See [docs/troubleshooting.md](docs/troubleshooting.md) for solutions to common issues including user namespace restrictions, missing `/dev/net/tun`, and AppArmor on Ubuntu 24.04+.

## How It Works

1. **Environment sanitization**: deny-by-default environment with only safe variables passed through.
2. **User namespace**: the child runs as uid 0 in an isolated namespace (no host privileges).
3. **Mount namespace**: paths specified with `--hide` are hidden via tmpfs overmounts.
4. **Landlock LSM**: filesystem access restricted to declared read-only, read-write, and execute paths.
5. **Network namespace + TAP**: child gets an isolated network with a virtual Ethernet device. A userspace TCP/IP stack (gvisor netstack) on the parent side filters traffic:
   - DNS queries checked against the domain allowlist
   - TLS connections validated via SNI
   - HTTP requests validated via Host header
   - All other ports dropped
