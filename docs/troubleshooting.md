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

`/dev/net/tun` is required for `--tun always` or `--proxy off --domains`. The default proxy mode (`--proxy on`) does not need `/dev/net/tun`.

To create the device node (requires root):

```
sudo mkdir -p /dev/net
sudo mknod /dev/net/tun c 10 200
sudo chmod 0666 /dev/net/tun
```

In containers, `/dev/net/tun` must be provided by the container runtime (e.g. `--device /dev/net/tun` in Docker/Podman). It is not in the [OCI default device list](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md).

## Running in Docker

Docker's default settings should work — no `--security-opt` flags are needed. Docker containers share the host kernel, so namespace and Landlock support depends on the host, not the container image.

For TUN mode (`--tun always` or `--proxy off --domains`), pass `--device /dev/net/tun` to `docker run`.

Run `./test/distro-smoke.sh` to verify curb works across Alpine, Debian, Fedora, Ubuntu, and Arch Linux containers. See the script header for options.

## AppArmor on Ubuntu 24.04+

Ubuntu 24.04+ restricts capabilities in user namespaces via the `unprivileged_userns` AppArmor profile. The default profile contains `audit deny capability,` which blocks all capability-gated operations including mount and TAP device creation.

The recommended fix is a dedicated AppArmor profile for curb. This is safer than modifying the global `unprivileged_userns` profile, which affects all programs.

### Dedicated profile (recommended)

Create `/etc/apparmor.d/curb` (adjust the binary path as needed):

```
abi <abi/4.0>,

include <tunables/global>

profile curb /usr/local/bin/curb {
  include <abstractions/base>

  # Allow user namespace creation.
  userns,

  # Mount operations inside user namespaces (pivot_root enforcement).
  capability sys_admin,

  # TAP device for network filtering (--domains).
  capability net_admin,

  # curb needs broad host file access for sandbox setup (bind mounts).
  # The sandboxed child is restricted by the namespace, not AppArmor.
  /** rwlkm,
  /dev/net/tun rw,
  /proc/** r,
  /sys/** r,

  # devpts nodes appear as disconnected paths in user namespaces.
  owner file rw dev/pts/[0-9]*,
}
```

Load the profile:

```
sudo apparmor_parser -r /etc/apparmor.d/curb
```

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
