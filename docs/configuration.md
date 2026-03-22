# Configuration

curb can be configured via CLI flags, environment variables, config files, and profiles. This document covers all four and how they interact.

## Priority order

Configuration is merged in this order (highest priority first):

1. **CLI flags** — always win.
2. **Environment variables** (`CURB_*`) — override config file values for scalars; additive for lists.
3. **Config files** (`.curb.yaml`) — prepended to list flags; scalars apply only if the flag was not set.
4. **Profiles** — lowest priority. List fields are merged additively; scalar fields apply only if the CLI flag was not set.

## Config files

Config files are YAML. curb auto-discovers `.curb.yaml` by walking up from the current directory. Use `-c`/`--config-file` or `CURB_CONFIG_FILE` to specify paths explicitly.

```yaml
domains:
  - pypi.org
  - "*.pythonhosted.org"
ips:
  - 10.0.0.0/8
read:
  - ~/.cache/pip
write:
  - .
exec:
  - python3
  - pip
env:
  - HOME
  - VIRTUAL_ENV
proxy: "on"
tun: auto
allow-http: false
unrestricted-net: false
```

Unknown keys are rejected. All fields are optional.

### List fields

`domains`, `ips`, `read`, `write`, `exec`, `env` — merged additively. Config file values are prepended to CLI values, so CLI exclusions (`!`) can override config file entries.

### Scalar fields

`proxy`, `tun`, `allow-http`, `allow-unix-sockets`, `unrestricted-net` — applied only when the corresponding CLI flag was not explicitly set.

## Profiles

Profiles are reusable config bundles for common toolchains. Each adds the right domains, paths, executables, and env vars.

```
curb -p node --write . -- npm install
curb -p go,git --write . -- go build ./...
```

Activate via `-p`/`--profiles`, `CURB_PROFILES`, or the `profiles:` field in a config file.

### Built-in profiles

| Profile | Includes | What it adds |
|---------|----------|-------------|
| `cc` | | C/C++ compiler toolchain (`gcc`, `clang`, internal tools in `/usr/libexec/gcc`) |
| `ssh` | | SSH keys, agent socket, `ssh`/`ssh-keygen` |
| `git` | `ssh` | Git/GPG config, `git`/`gpg` executables |
| `github` | `git` | GitHub API domains, `gh` CLI |
| `node` | | npm/yarn/pnpm registries, `node_modules` write, Node executables |
| `python` | | PyPI, pip cache, Python executables |
| `php` | | Packagist, Composer cache, `vendor` write |
| `go` | `cc` | Go module proxy, `~/go` read, `go` executable (includes C compiler for CGO) |
| `rust` | | crates.io, Cargo/Rustup home, `cargo`/`rustc` executables |
| `docker` | | Docker Hub registry, Docker socket |
| `claude-code` | | Anthropic API, Claude config, Node/Git executables |

All built-in profiles pass through `HOME` so that `~` paths resolve to the real home directory (see [HOME and tilde expansion](#home-and-tilde-expansion) below).

### Profile composition

Profiles can include other profiles via the `profiles:` field. Included profiles are loaded first (depth-first), and duplicates are deduplicated. Cycles are detected and rejected.

```yaml
# custom-ci.yaml
profiles:
  - git
  - node
domains:
  - internal-registry.dev
write:
  - .
```

Using `-p custom-ci` activates `ssh` (via `git`), `git`, `node`, and the custom profile's own config.

Scalar fields (like `allow-unix-sockets: true` in the `ssh` profile) are also applied from included profiles. If two profiles set conflicting values for the same scalar, curb reports an error.

### Custom profiles

Profiles are loaded from (in search order):

1. `$XDG_CONFIG_HOME/curb/profiles/` (default `~/.config/curb/profiles/`)
2. `/etc/curb/profiles/`
3. Built-in (embedded in the binary)

Profile names must match `[a-z0-9][a-z0-9-]*`. Create a YAML file with the same fields as a config file.

```
curb profile list          # list available profiles
curb profile show node     # show a profile's contents
```

## Environment variables

### `--env` syntax

The `--env` flag (and `CURB_ENV`, and the `env:` config/profile field) controls which environment variables the sandboxed process sees.

| Syntax | Effect |
|--------|--------|
| `--env NAME` | Pass through `NAME` from the host environment. |
| `--env NAME=VALUE` | Set `NAME` to `VALUE` explicitly. |
| `--env '*'` | Pass through all host variables (except curb internals). |
| `--env '!NAME'` | Remove `NAME` from the default passthrough list. |
| `--env '!*'` | Clear all defaults. |
| `--env '\!NAME'` | Escape literal `!` in a name. |

### Default variables

By default, curb sets:

- `TMPDIR` — a private temporary directory.
- `IS_SANDBOX=1` — signals to child processes that they are sandboxed.
- `HOME` — the sandbox home directory (see [HOME and tilde expansion](#home-and-tilde-expansion) below). Always set, even if not explicitly configured.

And passes through: `PATH`, `TERM`, `COLORTERM`, `NO_COLOR`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`, `USER`, `LOGNAME`, `SHELL`.

## HOME and tilde expansion

### How HOME is determined

The sandbox HOME is resolved in this order:

1. **`--env HOME=/path`** — explicit value wins.
2. **`--env HOME`** (passthrough) — host HOME is used.
3. **Fallback** — a private temporary directory (`/tmp/curb-xxx`).

HOME is always set. Even `--env '!HOME'` only prevents *passthrough*; the tmpDir fallback still applies.

### How `~` works in paths

`~` in `--read`, `--write`, `--exec`, config files, and profiles expands to the **sandbox HOME** — whatever HOME will be inside the sandbox.

- If HOME is passed through (`--env HOME`), `~` expands to your real home directory.
- If HOME is not passed through, `~` expands to the temporary sandbox directory. curb warns when this happens:

  ```
  curb: warning: ~ in paths resolves to temporary directory /tmp/curb-xxx
  (HOME not passed through); use --env HOME to use your real home
  ```

This means profiles that reference `~` paths (like `read: ["~/.ssh"]`) must include `HOME` in their `env:` list for those paths to point to real files. All built-in profiles do this.

### Why it works this way

`~` resolves to the sandbox HOME — not the host home — to prevent accidental exposure. Without this, activating a profile would grant host filesystem access to paths the sandboxed process can't even reach via `$HOME` (because `$HOME` inside the sandbox would be a different directory). By tying `~` to the sandbox HOME, profiles only grant meaningful access when the user has explicitly opted into HOME passthrough.

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

## Path expansion

Paths in `--read`, `--write`, `--exec`, config files, and profiles are expanded at plan time:

1. **Tilde expansion** — `~` and `~/` are replaced with the sandbox HOME directory (see above). `~username` is not supported.
2. **Glob expansion** — `*`, `?`, and `[` trigger glob matching (e.g. `--exec './dist/*/*'`).
3. **Relative path resolution** — `.` and `./...` are resolved to absolute paths.
4. **Symlink resolution** — symlinks in path lists are resolved so both the symlink and its target are covered. Note: symlinks *inside* mounted directories are not pre-resolved; if a file inside an allowed path is a symlink to an unallowed path, following it will fail.
