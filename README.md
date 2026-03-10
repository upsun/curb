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
curb -- make build
```

Allow HTTPS access to specific domains:

```
curb --allow-domains 'example.com,*.github.com' -- curl https://example.com
```

Allow a build tool to write to the current directory and access specific domains:

```
curb --allow-domains 'registry.npmjs.org,*.npmjs.org' -- npm install
```

Forward localhost services from the host:

```
curb --allow-domains '*' --allow-localhost -- curl http://127.0.0.1:8080/
```

Dry run to inspect the sandbox plan:

```
curb --dry-run -- make test
```

## CLI Reference

### Domain Filtering

| Flag | Env Var | Description |
|------|---------|-------------|
| `--allow-domains` | `CURB_ALLOW_DOMAINS` | Allowed domain patterns (comma-separated). Bare domains match exactly; use `*.example.com` for subdomains, or `*` to allow all. |

### Filesystem

| Flag | Env Var | Description |
|------|---------|-------------|
| `--fs-ro` | `CURB_FS_RO` | Additional read-only paths |
| `--fs-rw` | `CURB_FS_RW` | Additional read-write paths |
| `--fs-hide` | `CURB_FS_HIDE` | Paths to hide (overmounted with empty tmpfs) |

By default, system paths (`/usr`, `/lib`, `/etc`, etc.) are read-only, dotfiles are hidden, and Git working directories are writable. A private temp directory is created and set as `TMPDIR`.

### Executable Control

| Flag | Env Var | Description |
|------|---------|-------------|
| `--allow-exec` | `CURB_ALLOW_EXEC` | Additional allowed executables (name or absolute path) |

By default, only system binaries in `/usr/bin`, `/bin`, etc. and the target command itself have execute permission (via Landlock). Writable directories (TMPDIR, CWD) are not executable.

### Environment

| Flag | Env Var | Description |
|------|---------|-------------|
| `--env` | `CURB_ENV` | Pass through (`NAME`) or set (`NAME=VALUE`) env vars |
| `--env-passthrough` | `CURB_ENV_PASSTHROUGH` | Pass through the entire host environment |

By default, the environment is deny-by-default: only `HOME`, `PATH`, `SHELL`, `TMPDIR`, `TERM`, `TZ`, `LANG`, and a few other safe variables are passed through. Secrets (`*_KEY`, `*_TOKEN`, `*_SECRET`, etc.) are blocked.

### Logging

| Flag | Env Var | Description |
|------|---------|-------------|
| `--log-file` | `CURB_LOG_FILE` | Write structured JSON logs to file |
| `-v`, `--verbose` | `CURB_VERBOSE` | Print filtering decisions to stderr |

### Escape Hatches

| Flag | Description |
|------|-------------|
| `--no-fs-restrict` | Disable all filesystem restrictions |
| `--no-exec-restrict` | Disable executable restrictions |

### Network Options

| Flag | Description |
|------|-------------|
| `--allow-localhost` | Forward connections to 127.0.0.0/8 to the host |
| `--unsafe-allow-http` | Allow plaintext HTTP (port 80) when domain filtering is active |
| `--unsafe-allow-ech` | Allow TLS Encrypted Client Hello |
| `--unsafe-allow-no-sni` | Allow TLS connections without SNI |
| `--dns-upstream` | Override upstream DNS resolver address |

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

## How It Works

1. **Environment sanitization**: deny-by-default environment with only safe variables passed through.
2. **User namespace**: the child runs as uid 0 in an isolated namespace (no host privileges).
3. **Mount namespace**: dotfiles and sensitive paths are hidden via tmpfs overmounts; Git hooks directories are read-only.
4. **Landlock LSM**: filesystem access restricted to declared read-only, read-write, and execute paths.
5. **Network namespace + TAP**: child gets an isolated network with a virtual Ethernet device. A userspace TCP/IP stack (gvisor netstack) on the parent side filters traffic:
   - DNS queries checked against the domain allowlist
   - TLS connections validated via SNI
   - HTTP requests validated via Host header
   - All other ports dropped
