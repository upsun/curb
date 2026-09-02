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

`domains`, `ips`, `inject-header`, `read`, `write`, `exec`, `env` — merged additively. Config file values are prepended to CLI values, so CLI exclusions (`!`) can override config file entries.

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

## Credential injection

`--inject-header ENV_VAR:HOST[:PORT][,HOST...]` keeps a credential out of the
sandbox entirely. curb generates a stable placeholder for `ENV_VAR`, sets the
sandbox's copy of `ENV_VAR` to that placeholder (so the process never sees the
real value), and reads the real value from the *host's* `ENV_VAR`. Its proxy
terminates TLS for each destination, presenting a per-run CA that the sandbox
trusts, and replaces the placeholder with the real value wherever the client
placed it among the request headers on the way to the real upstream. The
credential is bound to those destinations only, so it is never attached to any
other host the program connects to.

A destination is `HOST[:PORT]`, where `HOST` is a hostname or IP literal and
`PORT` defaults to 443. The credential is injected only on the exact host:port —
a connection to the same host on a different port is relayed unchanged, with no
credential. A hostname must be exact: wildcards are rejected, since they cannot
identify the single destination a credential belongs to. Hostnames are matched
case-insensitively and a trailing dot is ignored. List several destinations,
comma-separated, when one credential is valid for more than one host
(`GH_TOKEN:api.github.com,uploads.github.com`). An IPv6 literal needs no
brackets on its own but must be bracketed when a port follows
(`TOK:[2001:db8::1]:8443`).

The binding is written variable-first because a credential belongs to its
variable and may be valid for more than one destination. The left side is always
an environment variable name — there is no literal form, because a literal would
have no variable through which to deliver the placeholder into the sandbox.

In a config file or profile, write a list item without a space after the colon
(`- GH_TOKEN:api.github.com`): that is a plain YAML string. Writing
`- GH_TOKEN: api.github.com` (with a space) makes YAML parse it as a mapping, and
curb rejects it.

Injection is **header-agnostic**: curb substitutes the placeholder in whatever
header the client emits, so it needs no knowledge of the host's auth scheme. The
same binding works whether the client sends `Authorization: Bearer <token>`,
`x-api-key: <token>`, or any other header — useful when the wire detail varies
across tools or changes over time, and so that a binding can be written by
someone who knows the credential's env var but not the API's header.

Injection is one-way: requests are rewritten, responses are relayed untouched.
If an endpoint on a bound host reflects request headers back — a debug or echo
endpoint, or an error response quoting the `Authorization` header — the
response carries the real credential into the sandbox. APIs do not normally do
this, but it means the binding protects the credential from the sandboxed
program, not from the bound host: bind a credential only to destinations it was
issued for.

Injection is opt-in per credential: if `ENV_VAR` is unset or empty on the host,
the binding is skipped silently (no error). This is what lets a profile carry an
injection that simply does nothing when the credential is absent.

An active injection binding does not grant network access by itself. Each
destination must also be allowed: a hostname by `--domains` (`CURB_DOMAINS`,
config, or a profile), an IP by `--ips`. If the credential is present but the
destination is not allowed, curb fails during planning instead of broadening the
sandbox policy.

Injection also requires the network proxy, so it cannot be combined with
`--unrestricted-net` (or run on a platform without network filtering): curb
fails during planning and suggests the alternative, an exact `--env ENV_VAR`
passthrough that puts the real credential in the sandbox instead.

```
# Real value read from the host's $GH_TOKEN; the sandbox sees only a placeholder,
# and gh sends it in whatever header it uses:
GH_TOKEN=ghp_xxx curb --domains api.github.com --inject-header 'GH_TOKEN:api.github.com' -- gh api user
```

The placeholder is constant per variable (e.g. `curb-inject-GH_TOKEN-placeholder`)
and carries no secret weight — the proxy overwrites it before the request leaves
the host. Keeping it stable means a tool that approves a custom credential (such
as Claude Code prompting to approve a custom API key) approves it once rather
than on every run.

The built-in **`claude`** profile does exactly this for Claude Code: it injects
`ANTHROPIC_API_KEY:api.anthropic.com`, so *when `ANTHROPIC_API_KEY` is set on the
host* the sandbox sees only the placeholder and the proxy substitutes the real
key in whichever header Claude Code sends (`x-api-key` or, for OAuth,
`Authorization`). With no host key set it is a no-op and OAuth/subscription auth
works unchanged. On first run Claude Code may prompt once to approve the
placeholder as a custom key.

The profile binding targets `api.anthropic.com`, so a custom `ANTHROPIC_BASE_URL`
(an internal gateway) is not covered: the gateway would receive the placeholder
and auth would fail. curb warns at plan time when it sees this — an endpoint
variable named after the credential (`ANTHROPIC_API_KEY` / `ANTHROPIC_BASE_URL`,
or any `<PREFIX>_BASE_URL`, `_API_BASE`, `_URL`, `_ENDPOINT`) that points
somewhere the credential is not bound:

```
curb: warning: ANTHROPIC_BASE_URL points at gateway.example.com, which
ANTHROPIC_API_KEY is not bound to (api.anthropic.com): requests there would
carry the placeholder instead of the credential; bind it with --inject-header
ANTHROPIC_API_KEY:gateway.example.com (allowing the host with --domains), or
pass the credential in with --env ANTHROPIC_API_KEY
```

For a gateway, either bind the key to its host as well —
`--inject-header ANTHROPIC_API_KEY:gateway.example.com` (bindings accumulate, so
both hosts inject) — or, if the gateway is trusted, pass the key through with an
exact `--env ANTHROPIC_API_KEY`. Exact passthrough (`--env ENV_VAR`) and an
explicit value (`--env ENV_VAR=value`) are treated as explicit trust decisions
and disable injection for that variable; wildcard passthrough such as
`--env 'ANTHROPIC_*'` or `--env '*'` does not.

The flag is repeatable (bindings accumulate). For active bindings, curb
extends each existing CA bundle from the standard CA environment variables
(`SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `REQUESTS_CA_BUNDLE`,
`NODE_EXTRA_CA_CERTS`) with the per-run CA and points that variable at the
extended bundle. If a variable is unset, curb uses the system roots as its base.
This lets common tools trust the terminated connection while preserving custom
trust for other hosts. A variable curb cannot extend — one pointing at a
*directory* of certificates (which cannot be extended by concatenation), or a
stale one pointing at a file that is missing or unreadable — does not fail the
run: curb warns and uses the system roots as that variable's base instead. Only
a missing system CA bundle is fatal, since then there is no trust store to hand
to the sandbox at all.

On **macOS**, tools built with Go 1.26 or earlier do not honor `SSL_CERT_FILE`:
Go's `crypto/x509` used the system keychain there and ignored those variables
until Go 1.27. Such a CLI (`gh`, `terraform`, `kubectl`, ... depending on the
Go version it was built with) will therefore reject the per-run CA and fail TLS
against a host with an injection binding, and curb has no way to deliver the CA
to it. Tools that read a CA bundle from the environment — curl, git, Python,
Node — are unaffected, as are Go tools built with Go 1.27 or later. On Linux all
of them honor `SSL_CERT_FILE`.

After terminating TLS, curb serves the decrypted stream as HTTP/1.1 — including
`Upgrade` flows such as WebSocket and `Expect: 100-continue` — and does not
negotiate HTTP/2 (no `h2` ALPN). An HTTP/2-only client or protocol — some gRPC
setups, for example — may fail against a host with injection enabled. Hosts
without an injection binding keep the untouched passthrough relay and are
unaffected.

Injection requires HTTPS. A plain-HTTP request to a bound host:port is refused
(injecting over cleartext would expose the credential), so a binding host should
be one the client reaches over TLS. The refusal is port-exact, like the binding:
plain HTTP to the same host on a port without a binding is relayed unchanged.
Injection applies on both the HTTPS proxy and the SOCKS5 path (used by tools
that route via `ALL_PROXY`), as long as the client sends the hostname
(`socks5h`, which curb advertises) rather than a pre-resolved IP.

It is also settable via the `CURB_INJECT_HEADER` environment variable, which
holds one full `ENV_VAR:HOST[,HOST...]` binding. For multiple bindings, repeat
the flag or use the `inject-header:` config-file/profile key. Values are merged
additively like `domains`. The value is resolved at run time wherever the
binding comes from, so prefer config files and profiles — only the variable name
is stored, never the token:

```yaml
# .curb.yaml — the value is read from the host's $GH_TOKEN at run time, not committed.
inject-header:
  - GH_TOKEN:api.github.com
```

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
