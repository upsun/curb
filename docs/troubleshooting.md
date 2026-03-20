# Troubleshooting

## User namespaces not available

If user namespaces are unavailable (Docker default seccomp, AppArmor restrictions, etc.), curb degrades to Landlock-only mode. This provides filesystem enforcement (read/write/exec restrictions) but no network filtering, mount namespace, PID isolation, or sub-path denials.

If Landlock is also unavailable, curb cannot run at all. To enable user namespaces:

```
sudo sysctl -w kernel.unprivileged_userns_clone=1
```

To make this permanent:

```
echo 'kernel.unprivileged_userns_clone=1' | sudo tee /etc/sysctl.d/99-userns.conf
sudo sysctl --system
```

## /dev/net/tun not available

`/dev/net/tun` is required for `--tun always` or `--proxy off --domains`. The default proxy mode (`--proxy on`) does not need `/dev/net/tun`.

To create the device node (requires root):

```
sudo mkdir -p /dev/net
sudo mknod /dev/net/tun c 10 200
sudo chmod 0666 /dev/net/tun
```

In containers, `/dev/net/tun` must be provided by the container runtime (e.g. `--device /dev/net/tun` in Docker/Podman). It is not in the [OCI default device list](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md).

## Running in Docker

Docker's default seccomp profile blocks `CLONE_NEWUSER`, so curb can only use Landlock-only mode (FS sandboxing, no network filtering). Pass `--unrestricted-net` to acknowledge unrestricted network:

```
curb --unrestricted-net -- command
```

To enable full sandboxing (network filtering, mount NS, PID isolation), add:

```
docker run --security-opt seccomp=unconfined --security-opt apparmor=unconfined ...
```

For TUN mode (`--tun always` or `--proxy off --domains`), also pass `--device /dev/net/tun`.

Docker containers share the host kernel, so Landlock support depends on the host (kernel 5.13+).

Run `./test/distro-smoke.sh` to verify curb works across Alpine, Debian, Fedora, Ubuntu, and Arch Linux containers. See the script header for options.

## AppArmor on Ubuntu 24.04+

Ubuntu 24.04+ restricts capabilities in user namespaces via the `unprivileged_userns` AppArmor profile. The default profile contains `audit deny capability,` which blocks all capability-gated operations including mount and TAP device creation.

The recommended fix is a dedicated AppArmor profile for curb. This is safer than modifying the global `unprivileged_userns` profile, which affects all programs.

### Install the profile

```
sudo curb apparmor install
```

This writes the profile to `/etc/apparmor.d/curb` and loads it. The command is idempotent. Use `--path /path/to/curb` if the binary is not in the default location.

To preview the profile without installing, run `curb apparmor`.

### Alternative: modifying the global profile

If a dedicated profile is not practical, modify the global `unprivileged_userns` profile. `deny` rules in AppArmor are final, so the `audit deny capability,` line must be commented out first.

Edit `/etc/apparmor.d/unprivileged_userns` to comment out `audit deny capability,`, then add to `/etc/apparmor.d/local/unprivileged_userns`:

```
# Mount operations (pivot_root enforcement).
capability sys_admin,

# TAP device for network filtering (--domains).
capability net_admin,

# devpts nodes appear as disconnected paths in user namespaces.
owner file rw dev/pts/[0-9]*,
```

Reload:

```
sudo apparmor_parser -r /etc/apparmor.d/unprivileged_userns
```

Note: this grants `sys_admin` and `net_admin` to **all** programs using unprivileged user namespaces, not just curb.

### Reloading AppArmor

SentinelOne or other endpoint security tools may silently block `apparmor_parser -r` on managed machines.
