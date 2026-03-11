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
| HTTPS to blocked domain | Blocked | curl exit 6, connection reset |
| HTTP to blocked domain | Blocked | Connection reset by peer |
| HTTPS by raw IP (DNS bypass) | Blocked | TLS terminated by netstack |
| TLS without SNI | Blocked | Connection killed (`UNEXPECTED_EOF`) |
| TLS with forged SNI (allowlisted name, blocked IP) | Blocked | Handshake timeout; netstack does not forward |
| Raw TCP send | Silently dropped | `connect()` and `send()` return success, but netstack accepts locally; data never leaves |
| DNS UDP to 8.8.8.8 | Intercepted | Returns RCODE=5 (REFUSED) for non-allowlisted domains |
| DNS TCP to 8.8.8.8 | Intercepted | Same REFUSED response |
| DNS subdomain exfiltration | Blocked | Query times out entirely |
| UDP to arbitrary port | Dropped | No response |
| Raw ICMP (ping) | Blocked | `CAP_NET_RAW` denied |
| Non-standard TCP port (8443) | Dropped | Send reports success but response is empty; no data forwarded |
| Localhost proxy (allowlisted) | Works | Reachable as expected |

## Analysis

The gvisor netstack intercepts all network traffic from the sandboxed process:

- **DNS filtering:** queries are handled by the netstack's DNS resolver, which only resolves allowlisted domains. Queries for other domains return REFUSED. Direct UDP/TCP DNS to external resolvers (e.g. 8.8.8.8) is also intercepted.
- **TLS SNI filtering:** only connections with an SNI matching the allowlist are forwarded on port 443. Connections without SNI or with a non-matching SNI are terminated.
- **HTTP Host filtering:** port 80 traffic is filtered by Host header (when `--allow-http` is enabled; otherwise port 80 is blocked entirely).
- **Non-HTTP/S ports:** TCP connections to other ports are accepted locally by the netstack but not forwarded. Data is silently dropped.
- **UDP:** non-DNS UDP traffic is dropped.
- **Raw sockets:** blocked by lack of `CAP_NET_RAW`.

## Observations

1. **TCP `connect()` always succeeds.** The netstack accepts connections locally in ~0ms, even to non-routable IPs (e.g. 192.0.2.1). `send()` also reports success. This is not a security issue (no data leaves the sandbox), but it means programs will not get connection errors for blocked destinations. They will instead see empty responses or timeouts on `recv()`.

2. **Credentials are properly isolated.** `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` are set to `proxy`, not real values. The proxy process outside the sandbox holds the real credentials and is reachable via the allowlisted localhost address.

3. **`_CURB_` internal env vars are filtered.** The `isInternalEnvVar()` check prevents curb's own control variables from leaking into the sandbox, including in passthrough-all mode.

## Conclusion

No data exfiltration to non-allowlisted domains was achieved. The network sandbox is functioning as designed.
