# curb

Sandbox any process. No root required.

curb runs commands inside a locked-down sandbox with default-deny filesystem, network, environment, and executable restrictions — using only unprivileged OS features (Linux namespaces/Landlock, macOS Seatbelt). Give a program access to exactly the domains and paths it needs, and nothing else.

## Why curb?

- **Single binary, no privileges** — no root, no Docker, no daemon.
- **Default-deny everything** — filesystem, network, environment variables, and executables are all blocked unless explicitly allowed.
- **Domain-level network filtering** — a proxy filters HTTP/HTTPS by domain, avoiding issues with Encrypted Client Hello (ECH).
- **Built-in profiles** — one flag (`-p node`, `-p go`, `-p python`, ...) adds the right domains, paths, and env vars for common toolchains.
- **Defense in depth** — mount namespaces + Landlock LSM for filesystem, proxy + optional userspace TCP/IP stack for network.
- **Fast** — the process starts in ~40 milliseconds.

## When not to use curb

- **Windows** — curb relies on Linux namespaces/Landlock or macOS Seatbelt. On Windows it applies environment sanitization only (no filesystem or network restrictions).
- **If you need root-level isolation** — curb runs entirely unprivileged. For multi-tenant or high security scenarios, a VM or container runtime is more appropriate, though the approaches can be combined.

## Installation

Clone the repository, then install with `go install`

## Quick start

Run a shell inside the sandbox:

```
curb
```

Run a command with default restrictions (read-only filesystem, no network, sanitized env):

```
curb make check
```

Allow network access to specific domains:

```
curb --domains 'example.com,*.github.com' -- curl https://example.com
```

Allow writes to the current directory:

```
curb --write . -- npm install
```

See what the sandbox will do without running anything:

```
curb --dry-run make test
```

## Profiles

Profiles are reusable config bundles for common toolchains. Each one adds the right domains, paths, executables, and env vars — so you don't have to spell them out every time.

```
curb -p node --write . -- npm install
```

```
curb -p go --write . -- go build ./...
```

```
curb -p python --write . -- pip install -r requirements.txt
```

Combine profiles freely:

```
curb -p node,github --write . -- npm install
```

### Built-in profiles

| Profile | What it allows |
|---------|---------------|
| `node` | npm/yarn/pnpm registries, `node_modules` write, Node executables |
| `python` | PyPI, pip cache, Python executables |
| `php` | Packagist, Composer cache, `vendor` write |
| `go` | Go module proxy, `~/go` read, `go` executable |
| `rust` | crates.io, Cargo/Rustup home, `cargo`/`rustc` executables |
| `git` | GitHub/GitLab/Bitbucket, SSH keys, Git config |
| `github` | GitHub API and raw content domains, `gh` CLI |
| `docker` | Docker Hub registry, Docker socket |
| `claude-code` | Anthropic API, Claude config, Node executables |

List and inspect profiles:

```
curb profile list
curb profile show node
```

Override profile defaults from the CLI (profiles are lowest priority, CLI flags win):

```
curb -p node --write . --domains '*.npmjs.org,registry.internal.dev' -- npm install
```

Profiles can also be activated via config file (`.curb.yaml`) or environment variable (`CURB_PROFILES=node,git`).

## Examples

Sandbox a build that needs network access and writes to the project directory:

```
curb -p node --write . -- npm run build
```

Run tests with no network and no writes (the default):

```
curb make test
```

Allow access to specific IP ranges (e.g. a local service):

```
curb --ips '192.168.1.0/24' -- python3 client.py
```

Forward localhost services from the host into the sandbox:

```
curb --domains localhost -- curl http://127.0.0.1:8080/
```

Hide a sensitive file under an otherwise-allowed path:

```
curb --read /etc --read '!/etc/shadow' -- cat /etc/passwd
```

Allow unrestricted network but keep filesystem restrictions:

```
curb --unrestricted-net -- ./my-script.sh
```

Pass through a specific environment variable:

```
curb --env 'DATABASE_URL' -- ./migrate.sh
```

## CLI reference

### Network

| Flag | Env var | Description |
|------|---------|-------------|
| `--domains` | `CURB_DOMAINS` | Allowed domain patterns (comma-separated). `*.example.com` for subdomains, `*` to allow all, `localhost` for localhost forwarding. |
| `--ips` | `CURB_IPS` | Allowed IP addresses or CIDR ranges (e.g. `10.0.0.1`, `192.168.0.0/16`, `::1`). |
| `--unrestricted-net` | `CURB_UNRESTRICTED_NET` | Skip network filtering entirely. Cannot combine with `--domains` or `--ips`. |

### Filesystem

| Flag | Env var | Description |
|------|---------|-------------|
| `--read` | `CURB_READ` | Readable paths. `!` prefix denies, `!*` clears defaults. Glob patterns supported. |
| `--write` | `CURB_WRITE` | Writable paths. `!` prefix makes read-only, `*` disables FS restrictions. |

Defaults: system paths (`/usr`, `/lib`, `/proc`), select `/etc` files (DNS, TLS certs, timezone, passwd), device nodes (`/dev/null`, `/dev/urandom`), and the current directory (read-only). A private temp directory is created and set as `TMPDIR`.

### Executables

| Flag | Env var | Description |
|------|---------|-------------|
| `--exec` | `CURB_EXEC` | Allowed executables. `!` prefix removes defaults, `*` allows all. |

Default: system binaries in `/usr/bin`, `/bin`, etc. Writable directories are not executable.

### Environment

| Flag | Env var | Description |
|------|---------|-------------|
| `--env` | `CURB_ENV` | Pass through (`NAME`) or set (`NAME=VALUE`) env vars. `!` prefix removes defaults, `*` passes all. |

Default: deny-by-default. Only `PATH`, `TMPDIR`, `TERM`, `TZ`, `LANG`, and a few safe variables are passed. `HOME` defaults to a private temporary directory; use `--env HOME` to pass through the host HOME. See [docs/configuration.md](docs/configuration.md) for details on HOME and tilde expansion.

### Configuration

| Flag | Env var | Description |
|------|---------|-------------|
| `-c`, `--config-file` | `CURB_CONFIG_FILE` | Config file path(s). Default: auto-discover `.curb.yaml`. |
| `-p`, `--profiles` | `CURB_PROFILES` | Activate named profiles (comma-separated). |
| `--dry-run` | | Print the sandbox plan without running anything. |

### Output

| Flag | Env var | Description |
|------|---------|-------------|
| `--log-file` | `CURB_LOG_FILE` | Write structured JSON logs to file. |
| `-v`, `--verbose` | `CURB_VERBOSE` | Print filtering decisions to stderr. |
| `-q`, `--quiet` | `CURB_QUIET` | Suppress warnings. |

## The `!` prefix

Use `!` to deny access to specific paths, env vars, or executables — even if a parent path is allowed:

```
--read /etc --read '!/etc/shadow'      # hide /etc/shadow
--write /data --write '!/data/config'  # make /data/config read-only
--exec '!/usr/bin/curl'                # block curl
--env '!USER'                          # remove USER from defaults
```

`!*` clears all defaults for a flag. `\!` escapes a literal `!`.

Sub-path denials (`!` under an allowed parent) require mount namespace support. Landlock-only mode warns if these cannot be enforced.

## Platform support

| Platform | Sandbox level | Notes |
|----------|--------------|-------|
| Linux (kernel 5.13+, mount ops) | Full | pivot_root + Landlock + MITM proxy |
| Linux (kernel 5.13+, no mount ops) | Strong | Landlock + MITM proxy; blocked paths return EACCES not ENOENT |
| Linux (kernel 3.8-5.12, mount ops) | Strong | pivot_root + MITM proxy (no Landlock hardening) |
| macOS | Strong | Seatbelt (sandbox-exec) + MITM proxy |
| Windows | Env only | Environment sanitization only |

### macOS notes

macOS uses Apple's Seatbelt (`sandbox-exec`) for kernel-enforced filesystem and network restrictions. The same CLI flags work on macOS with these differences:

- **No PID isolation** — macOS has no PID namespaces.
- **`--ips` without `--domains`** — works directly via Seatbelt IP rules (no proxy needed).
- **`sandbox-exec` is marked deprecated** since macOS 10.7 but remains functional and is used by Codex, Homebrew, and Apple's own tools.

## How it works

### Linux

1. **Environment sanitization** — deny-by-default env with only safe variables passed through.
2. **User namespace** — the child runs as uid 0 in an isolated namespace (no host privileges).
3. **Mount namespace + pivot_root** — a new root is built from bind-mounted allowed paths. Unmounted paths don't exist. `MS_RDONLY` and `MS_NOEXEC` enforce write and exec restrictions. Landlock layers on top for defense in depth.
4. **Network namespace + MITM proxy** — the child gets isolated loopback only. An ephemeral CA and MITM proxy in the parent filter HTTP/HTTPS by domain, regardless of Encrypted Client Hello (ECH). A SOCKS5 proxy handles non-HTTP TCP (e.g. SSH via ProxyCommand). Programs ignoring proxy settings get no network.

### macOS

1. **Environment sanitization** — same deny-by-default approach.
2. **Seatbelt profile** — an SBPL (Seatbelt Profile Language) profile is generated from the sandbox plan with `(deny default)` and explicit allow rules for permitted paths, executables, and network endpoints.
3. **sandbox-exec** — the child is spawned under `/usr/bin/sandbox-exec -p '<profile>'`. The Seatbelt profile is inherited by all child processes.
4. **MITM proxy** — same ephemeral CA and proxy as Linux, running on localhost. The Seatbelt profile allows only the proxy port for outbound connections.

## Troubleshooting

See [docs/troubleshooting.md](docs/troubleshooting.md) for solutions to common issues including user namespace restrictions, AppArmor on Ubuntu 24.04+, and running in Docker.

## Further reading

- [Configuration guide](docs/configuration.md) — profiles, config files, environment variables, HOME and tilde expansion
- [Comparison with Anthropic's sandbox-runtime](docs/comparison-sandbox-runtime.md)
