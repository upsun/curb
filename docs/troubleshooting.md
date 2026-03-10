# Troubleshooting

## User namespaces not available

curb requires unprivileged user namespaces. If they are disabled:

```
sudo sysctl -w kernel.unprivileged_userns_clone=1
```

To make this permanent:

```
echo 'kernel.unprivileged_userns_clone=1' | sudo tee /etc/sysctl.d/99-userns.conf
sudo sysctl --system
```

## /dev/net/tun not available

`/dev/net/tun` is required for `--allow-domains` and `--allow-localhost`. Without it, curb can only offer all-or-nothing network isolation.

To create the device node (requires root):

```
sudo mkdir -p /dev/net
sudo mknod /dev/net/tun c 10 200
sudo chmod 0666 /dev/net/tun
```

In containers, `/dev/net/tun` must be provided by the container runtime (e.g. `--device /dev/net/tun` in Docker/Podman). It is not in the [OCI default device list](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md).

## AppArmor on Ubuntu 24.04+

Ubuntu 24.04+ restricts capabilities in user namespaces via the `unprivileged_userns` AppArmor profile. The default profile contains `audit deny capability,` which blocks all capability-gated operations. `deny` rules in AppArmor are final and cannot be overridden by `allow` rules in local includes -- the `deny` line must be commented out first.

### TAP creation fails (TUNSETIFF: operation not permitted)

Required for `--allow-domains` / `--allow-localhost`. Comment out `audit deny capability,` in `/etc/apparmor.d/unprivileged_userns`, then add to `/etc/apparmor.d/local/unprivileged_userns`:

```
capability net_admin,
```

For mount namespace features (`--hide`, DNS via mount), also add:

```
capability sys_admin,
```

### fstat errors on terminal devices

The AppArmor profile only allows file access on absolute paths (`/**`). In user namespaces, devpts nodes appear as disconnected paths (`dev/pts/0` without leading `/`), causing `fstat()` to fail with EACCES.

This affects programs that call `fstat()` on inherited terminal file descriptors (e.g. Bun, Node.js). Programs that only `write()` (echo, printf) are unaffected.

Add to `/etc/apparmor.d/local/unprivileged_userns`:

```
owner file rw dev/pts/[0-9]*,
```

### Reloading AppArmor

After editing, reload the profile:

```
sudo apparmor_parser -r /etc/apparmor.d/unprivileged_userns
```

Note: SentinelOne or other endpoint security tools may silently block `apparmor_parser -r` on managed machines.
