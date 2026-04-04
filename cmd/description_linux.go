package cmd

const longDescription = `Enforcement on Linux:
  - Filesystem: mount namespace (pivot_root) + Landlock (when available)
  - Network: domain/IP filtering via HTTP + SOCKS5 proxy
  - Executables: Landlock EXECUTE
  - Unix sockets: seccomp AF_UNIX filter
  - Environment: deny-by-default passthrough`
