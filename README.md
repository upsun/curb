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
curb --allow-domains 'example.com,*.github.com' -- curl https://example.com
```

Allow a build tool to write to the current directory and access specific domains:

```
curb --allow-write . --allow-domains 'registry.npmjs.org,*.npmjs.org' -- npm install
```

Forward localhost services from the host:

```
curb --allow-domains '*' --allow-localhost -- curl http://127.0.0.1:8080/
```

Dry run to inspect the sandbox plan:

```
curb --dry-run make test
```

## CLI Reference

### Network

| Flag | Env Var | Description |
|------|---------|-------------|
| `--allow-domains` | `CURB_ALLOW_DOMAINS` | Allowed domain patterns (comma-separated). Bare domains match exactly; use `*.example.com` for subdomains, or `*` to allow all. |
| `--allow-localhost` | `CURB_ALLOW_LOCALHOST` | Forward connections to 127.0.0.0/8 to the host |
| `--allow-http` | `CURB_ALLOW_HTTP` | Allow plaintext HTTP (port 80) when domain filtering is active |
| `--ech` | `CURB_ECH` | ECH handling mode: `strip` (default, strips ECH from DNS), `allow`, `deny` |
| `--allow-no-sni` | `CURB_ALLOW_NO_SNI` | Allow TLS connections without SNI (reduces filtering) |

### Filesystem

| Flag | Env Var | Description |
|------|---------|-------------|
| `--allow-read` | `CURB_ALLOW_READ` | Additional readable paths (use `'*'` to allow all reads) |
| `--allow-write` | `CURB_ALLOW_WRITE` | Additional writable paths (use `'*'` to disable all FS restrictions) |
| `--hide` | `CURB_HIDE` | Paths to hide (overmounted with empty tmpfs) |

By default, system paths (`/usr`, `/lib`, `/etc`, `/proc`), device nodes (`/dev/null`, `/dev/urandom`, `/dev/pts`), and the current directory are accessible. A private temp directory is created and set as `TMPDIR`. Use `--allow-write .` to grant write access to the current directory. Use `--hide` to hide sensitive paths (e.g. `--hide ~/.ssh`). Glob patterns are supported (e.g. `--allow-read '~/docs/*.md'`).

### Executable Control

| Flag | Env Var | Description |
|------|---------|-------------|
| `--allow-exec` | `CURB_ALLOW_EXEC` | Additional allowed executables (use `'*'` to allow all) |

By default, only system binaries in `/usr/bin`, `/bin`, etc. and the target command itself have execute permission (via Landlock). Writable directories (TMPDIR) are not executable.

### Environment

| Flag | Env Var | Description |
|------|---------|-------------|
| `--allow-env` | `CURB_ALLOW_ENV` | Pass through (`NAME`) or set (`NAME=VALUE`) env vars (use `'*'` for all) |

By default, the environment is deny-by-default: only `HOME`, `PATH`, `SHELL`, `TMPDIR`, `TERM`, `TZ`, `LANG`, and a few other safe variables are passed through. Secrets (`*_KEY`, `*_TOKEN`, `*_SECRET`, etc.) are blocked.

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
| `--home` | Custom writable home directory path |

## Platform Support

| Platform | Restrictions | Notes |
|----------|-------------|-------|
| Linux (kernel 5.13+) | Full | Landlock + namespaces + netstack |
| Linux (kernel 4.18-5.12) | Degraded | No Landlock; mount/seccomp only |
| macOS / Windows | Environment only | Sanitized env; all other restrictions unavailable |

## Troubleshooting

### AppArmor on Ubuntu 24.04+

Ubuntu 24.04+ restricts user namespaces via the `unprivileged_userns` AppArmor profile. This can cause two issues:

**TUN/TAP creation fails** (`--allow-domains`): Add capabilities to `/etc/apparmor.d/local/unprivileged_userns`:

```
capability net_admin,
```

**`fstat` errors on terminal devices** (e.g. `EACCES: permission denied, fstat` from Bun/Node): The AppArmor profile only allows file access on absolute paths (`/**`), but devpts nodes in a user namespace appear as disconnected paths (`dev/pts/0` without leading `/`). Add to `/etc/apparmor.d/local/unprivileged_userns`:

```
owner file rw dev/pts/[0-9]*,
```

After editing, reload the profile:

```
sudo apparmor_parser -r /etc/apparmor.d/unprivileged_userns
```

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
