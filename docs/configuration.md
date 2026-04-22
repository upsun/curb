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
unrestricted-net: false
```

Unknown keys are rejected. All fields are optional.

### List fields

`domains`, `ips`, `read`, `write`, `exec`, `env` — merged additively. Config file values are prepended to CLI values, so CLI exclusions (`!`) can override config file entries.

### Scalar fields

`allow-unix-sockets`, `host-loopback`, `unrestricted-net` — applied only when the corresponding CLI flag was not explicitly set.

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
| `ruby` | | RubyGems, gem/bundle cache, `vendor` write, Ruby executables |
| `rust` | | crates.io, Cargo/Rustup home, `cargo`/`rustc` executables |
| `docker` | | Docker Hub registry, Docker socket |
| `make` | | `make` executable and common Makefile shell tools |
| `claude` | | Anthropic API, Claude config, system/Git executables |
| `gemini` | | Google AI APIs, Gemini CLI config, system/Git executables |
| `codex` | | OpenAI API, Codex config, system/Git executables |
| `opencode` | | Common AI provider APIs, OpenCode config, system/Git executables |
| `vibe` | | Mistral AI API, Vibe config, system/Git executables |
| `copilot` | | GitHub Copilot API, Copilot config, system/Git executables |
| `shell` | | System binary directories (`/usr/bin`, `/bin`, etc.) for interactive sessions |
| `xcode` | | macOS Xcode/Command Line Tools paths (darwin only) |

Built-in profiles that reference `~` paths pass through `HOME` so those paths resolve to the real home directory (see [HOME and tilde expansion](#home-and-tilde-expansion) below).

Profile `exec` entries are resolved via `$PATH` and added alongside the dynamic linker directories (`/lib`, `/lib64` on Linux), which are always executable. On NixOS/Guix, the dynamic linker lives under `/nix/store/...` — use `--exec /nix/store/<hash>-glibc/lib` or equivalent.

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

### Platform-specific overlays

Profiles can have a platform overlay file named `<name>_<GOOS>.yaml` (currently `_linux` or `_darwin`). It is auto-merged when `<name>` is loaded on the matching OS, and invisible otherwise. Overlays are a filename-only convention — they are never referenced by name; users (and other profiles' `profiles:` fields) always refer to the base name.

For example, `-p python` on macOS merges `python.yaml` plus the built-in `python_darwin.yaml` overlay (which adds Homebrew-installed Python paths); on Linux no overlay exists and only the base loads. Overlays are one level deep: `foo_darwin` does not itself get an `foo_darwin_darwin` overlay.

A profile that only makes sense on one OS can be shipped as the overlay file alone, with no base. The built-in `xcode` profile is one such case: `xcode_darwin.yaml` is the only file, so `-p xcode` on macOS loads it as the profile; on Linux `-p xcode` fails with "profile 'xcode' is only available on darwin".

### Custom profiles

Profiles are loaded from (in search order):

1. `$XDG_CONFIG_HOME/curb/profiles/` (default `~/.config/curb/profiles/`)
2. `/etc/curb/profiles/`
3. Built-in (embedded in the binary)

Profile names must match `[a-z0-9][a-z0-9-]*`. Underscores are reserved for the overlay filename convention above and are not allowed in referenceable names.

```
curb profile list          # list available profiles
curb profile show node     # show a profile's contents
```

### Auto-profile matching

Instead of specifying a profile manually, `--auto` (or `-a`) selects a profile based on the command name.

```
curb --auto npm install        # auto-selects the "node" profile
curb -a cargo build            # auto-selects the "rust" profile
curb -a /usr/bin/python3 app.py  # auto-selects the "python" profile
```

Enable via:

| Method | Example |
|--------|---------|
| CLI flag | `--auto` / `-a` |
| Env var | `CURB_AUTO=1` |
| Config file | `auto: true` |

How it works: curb takes the basename of the first command argument and searches all available profiles for a matching `commands:` field. The first profile whose `commands` list contains the basename is activated. If no profile matches, curb proceeds without one (no error).

The auto-matched profile is prepended to the profile list with lowest precedence, so explicit `-p` profiles and config file profiles override it. If the auto-matched profile was already activated explicitly, it is not duplicated.

User-defined profiles can participate by adding a `commands:` field:

```yaml
# ~/.config/curb/profiles/mydb.yaml
commands: [psql, pg_dump, pg_restore]
domains:
  - db.example.com
env:
  - PGPASSWORD
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
- `CURB_SKILL_DIR` — path to the [Agent Skills](https://agentskills.io/) directory containing `SKILL.md` with the active sandbox constraints (filesystem, network, environment). Also written to `~/.agents/skills/curb/` (with a symlink at `~/.claude/skills/curb/`) for automatic discovery by compatible agents. When HOME is passed through (`--env HOME`) and mount namespaces are available, the skill directory is bind-mounted under the real HOME on Linux and auto-included in the read allowlist; on macOS or without mount namespaces, auto-discovery only works from the default sandbox HOME and the env var is the fallback.
- `HOME` — the sandbox home directory (see [HOME and tilde expansion](#home-and-tilde-expansion) below). Always set, even if not explicitly configured.

And passes through: `PATH`, `TERM`, `COLORTERM`, `NO_COLOR`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`, `USER`, `LOGNAME`, `SHELL`.

## HOME and tilde expansion

### How HOME is determined

The sandbox HOME is resolved in this order:

1. **`--env HOME=/path`** — explicit value wins.
2. **`--env HOME`** (passthrough) — host HOME is used.
3. **Fallback** — a private temporary directory (`/tmp/curb-xxx`).

HOME is always set. Even `--env '!HOME'` only prevents *passthrough*; the tmpDir fallback still applies.

### How `~` and `$HOME` work in paths

`~`, `~/`, and `$HOME` in `--read`, `--write`, `--exec`, config files, and profiles all resolve to the **host** home directory — the same thing the shell would substitute on the command line. `~`/`$HOME` are host-side shorthands: they are not re-mapped to the sandbox's HOME even if `--env HOME=/path` changes what the sandboxed process sees.

For a granted path under the host home to be reachable by the sandboxed program via its own `$HOME`, the sandbox HOME has to equal the host HOME — i.e. HOME must be passed through (`--env HOME`). curb warns at plan time when a profile or config entry uses `~` or `$HOME` and the sandbox's HOME will differ:

```
curb: warning: ~ or $HOME in paths resolves to the host home (/home/user),
but the sandbox's $HOME will be /tmp/curb-xxx — the sandboxed program
cannot reach these paths via its own $HOME. Use --env HOME to align
them, or ignore this warning if you meant the host path.
```

The warning only fires for paths that reference the host home symbolically (`~`, `~/...`, `$HOME`, `${HOME}`). An explicit literal like `read: ["/home/user/.ssh"]` is treated as the user's deliberate choice and does not warn. Shell-expanded CLI paths (`~/foo` becomes `/home/user/foo` before curb sees it) are equivalent to literals and also don't warn.

Built-in profiles that reference `~` paths (like `read: ["~/.ssh"]`) include `HOME` in their `env:` list so `curb --profile foo` needs no extra flags. User-authored profiles should do the same, unless they genuinely want to grant the host home to a program whose `$HOME` will point elsewhere.

If `os.UserHomeDir()` cannot determine a host home (e.g. `$HOME` is unset and no passwd entry exists) and any configured path uses `~`, curb refuses to build the sandbox rather than silently expanding `~/.ssh` to `/.ssh`.

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

1. **Tilde expansion** — `~` and `~/` are replaced with the host home directory (see above). `~username` is not supported.
2. **Environment variable expansion** — `$VAR` and `${VAR}` in `read`, `write`, and `exec` entries of config files and profiles are expanded against the **host** environment at merge time. Entries that reference an unset variable or expand to an empty string are dropped with a warning. Write a literal `$` as `$$` (Make convention); a literal `$$` is `$$$$`. CLI flags (`--read` etc.) are passed through the shell and are not re-expanded by curb.
3. **Glob expansion** — `*`, `?`, and `[` trigger glob matching (e.g. `--exec './dist/*/*'`).
4. **Relative path resolution** — `.` and `./...` are resolved to absolute paths.
5. **Symlink resolution** — symlinks in path lists are resolved so both the symlink and its target are covered. Note: symlinks *inside* mounted directories are not pre-resolved; if a file inside an allowed path is a symlink to an unallowed path, following it will fail.
