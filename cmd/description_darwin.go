package cmd

const longDescription = `Enforcement on macOS:
  - Filesystem: Seatbelt (sandbox-exec) with SBPL rules
  - Network: domain/IP filtering via HTTP + SOCKS5 proxy
  - Unix sockets: Seatbelt AF_UNIX deny
  - Environment: deny-by-default passthrough`
