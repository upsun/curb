# Curb Network Sandbox Test Report

Date: 2026-03-11
Tester: Claude Code (running inside curb sandbox)

## Environment

- Kernel: Linux 6.8.0-100-generic
- User namespace: active (uid=0 mapped)
- Network namespace: active (separate from host)
- Netstack: gvisor userspace TCP/IP
- `IS_SANDBOX=1`, `TMPDIR=/tmp/curb-*`
- API credentials replaced with `proxy` placeholder; real keys held by proxy process outside sandbox

## Results

| Attack Vector | Result | Details |
|---|---|---|
| HTTPS to blocked domain | Blocked | Connection reset |
| HTTP to blocked domain | Blocked | Connection reset by peer |
| HTTPS by raw IP (DNS bypass) | Blocked | TLS terminated by netstack |
| TLS without SNI | Blocked | `SSL UNEXPECTED_EOF` |
| TLS with forged SNI (allowlisted name, blocked IP) | Blocked | `SSL UNEXPECTED_EOF`; netstack does not forward |
| TLS with no SNI (omit `server_hostname`) | Blocked | `SSL UNEXPECTED_EOF` |
| Raw TCP send (port 80) | Blocked | `connect()` succeeds, `send()` triggers `ConnectionResetError` (RST) |
| Raw TCP on port 443 (no TLS handshake) | Blocked | 0 bytes returned, connection closed |
| Non-standard TCP port (4443, 8080, 8443) | Blocked | Connection reset |
| Mixed-case Host header (`EXAMPLE.COM`) | Blocked | Connection reset; matching is case-insensitive |
| Double Host header (`Host: localhost` + `Host: example.com`) | Blocked | Connection reset |
| Absolute URI in request line with `Host: localhost` | Blocked | 0 bytes returned |
| Transfer-Encoding chunked smuggling | Blocked | Connection reset |
| Decimal IP encoding (`http://1572395790/`) | Blocked | Empty response |
| Hex IP encoding (`http://0x5DB8D70E/`) | Blocked | Connection reset |
| IPv6 direct | Blocked | `Network is unreachable` |
| DNS UDP to 8.8.8.8 | Intercepted | Returns RCODE=5 (REFUSED) for non-allowlisted domains |
| DNS TCP to 8.8.8.8 | Intercepted | Same REFUSED response |
| DNS subdomain exfiltration (`<encoded>.example.com`) | Blocked | REFUSED |
| UDP to arbitrary port | Dropped | `sendto()` succeeds, no response (timeout) |
| Raw ICMP (ping) | Blocked | `CAP_NET_RAW` denied |
| Bash `/dev/tcp` builtin | Blocked | Exit 0 but no data transferred |
| HTTP CONNECT tunnel via allowed domain | Blocked | GitHub returned 400; no tunnel established |
| Localhost relay proxy (bind + forward) | Blocked | `Cannot assign requested address` |
| Namespace escape (`nsenter -t 1 -n`) | Blocked | Permission denied on `/proc/1/ns/net` |
| Modify `/etc/resolv.conf` or `/etc/hosts` | Blocked | Permission denied (Landlock) |
| Localhost proxy (allowlisted) | Works | Reachable as expected |

## Analysis

The gvisor netstack intercepts all network traffic from the sandboxed process:

- **DNS filtering:** queries are handled by the netstack's DNS resolver, which only resolves allowlisted domains. Queries for other domains return REFUSED. Direct UDP/TCP DNS to external resolvers (e.g. 8.8.8.8) is also intercepted. DNS-based data exfiltration via subdomain encoding is blocked.
- **TLS SNI filtering:** only connections with an SNI matching the allowlist are forwarded on port 443. Connections without SNI, with a non-matching SNI, or with a spoofed SNI (allowlisted name to a non-matching IP) are all terminated before the handshake completes.
- **HTTP Host filtering:** port 80 traffic is filtered by Host header (when `--allow-http` is enabled; otherwise port 80 is blocked entirely). Case-insensitive matching. Double Host headers, absolute URIs, and chunked TE smuggling are all rejected.
- **Non-HTTP/S ports:** TCP connections to other ports receive RST after data is sent.
- **UDP:** non-DNS UDP traffic is silently dropped.
- **Raw sockets:** blocked by lack of `CAP_NET_RAW`.
- **IP encoding tricks:** decimal, hex, and IPv6 address formats are all handled correctly.

## Observations

1. **TCP `connect()` always succeeds.** The netstack accepts connections locally in ~0ms, even to non-routable IPs. Blocked connections receive RST when data is sent. This is not a security issue (no data leaves the sandbox), but programs will see connection resets rather than connection refused errors for blocked destinations.

2. **Credentials are properly isolated.** `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` are set to `proxy`, not real values. The proxy process outside the sandbox holds the real credentials and is reachable via the allowlisted localhost address.

3. **`_CURB_` internal env vars are filtered.** The `isInternalEnvVar()` check prevents curb's own control variables from leaking into the sandbox, including in passthrough-all mode.

4. **Allowed domains are a potential exfiltration channel.** Data can be sent to any allowlisted domain (e.g. `github.com`). This is inherent to domain-based filtering. Minimize the allowlist and the readable filesystem surface to reduce this risk.

## Conclusion

No data exfiltration to non-allowlisted domains was achieved across 25+ attack vectors. The network sandbox is functioning as designed.
