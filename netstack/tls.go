package netstack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

var (
	errNotClientHello = errors.New("not a TLS ClientHello")
	errTruncated      = errors.New("truncated TLS record")
)

const (
	tlsContentTypeHandshake = 0x16
	tlsHandshakeClientHello = 0x01
	tlsExtSNI               = 0x0000
	tlsExtECH               = 0xfe0d
	tlsSNIHostNameType       = 0x00
	tlsMaxRead              = 16384
	tlsReadTimeout          = 10 * time.Second
)

// ParseClientHello extracts the SNI hostname and ECH presence from a TLS
// ClientHello message. data must start with the TLS record header.
func ParseClientHello(data []byte) (sni string, hasECH bool, err error) {
	// TLS record header: content_type(1) + version(2) + length(2) = 5 bytes.
	if len(data) < 5 {
		return "", false, errTruncated
	}
	if data[0] != tlsContentTypeHandshake {
		return "", false, errNotClientHello
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	payload := data[5:]
	if len(payload) < recordLen {
		return "", false, errTruncated
	}
	payload = payload[:recordLen]

	// Handshake header: type(1) + length(3) = 4 bytes.
	if len(payload) < 4 {
		return "", false, errTruncated
	}
	if payload[0] != tlsHandshakeClientHello {
		return "", false, errNotClientHello
	}
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	payload = payload[4:]
	if len(payload) < hsLen {
		return "", false, errTruncated
	}
	payload = payload[:hsLen]

	// ClientHello body: version(2) + random(32) = 34 bytes.
	if len(payload) < 34 {
		return "", false, errTruncated
	}
	payload = payload[34:]

	// Session ID (variable length).
	if len(payload) < 1 {
		return "", false, errTruncated
	}
	sidLen := int(payload[0])
	payload = payload[1:]
	if len(payload) < sidLen {
		return "", false, errTruncated
	}
	payload = payload[sidLen:]

	// Cipher suites (variable length).
	if len(payload) < 2 {
		return "", false, errTruncated
	}
	csLen := int(binary.BigEndian.Uint16(payload[:2]))
	payload = payload[2:]
	if len(payload) < csLen {
		return "", false, errTruncated
	}
	payload = payload[csLen:]

	// Compression methods (variable length).
	if len(payload) < 1 {
		return "", false, errTruncated
	}
	cmLen := int(payload[0])
	payload = payload[1:]
	if len(payload) < cmLen {
		return "", false, errTruncated
	}
	payload = payload[cmLen:]

	// Extensions (optional).
	if len(payload) < 2 {
		// No extensions — valid but no SNI.
		return "", false, nil
	}
	extLen := int(binary.BigEndian.Uint16(payload[:2]))
	payload = payload[2:]
	if len(payload) < extLen {
		return "", false, errTruncated
	}
	payload = payload[:extLen]

	// Parse each extension.
	for len(payload) >= 4 {
		extType := binary.BigEndian.Uint16(payload[:2])
		extDataLen := int(binary.BigEndian.Uint16(payload[2:4]))
		payload = payload[4:]
		if len(payload) < extDataLen {
			return "", false, errTruncated
		}
		extData := payload[:extDataLen]
		payload = payload[extDataLen:]

		switch extType {
		case tlsExtSNI:
			name := parseSNIExtension(extData)
			if name != "" {
				sni = name
			}
		case tlsExtECH:
			hasECH = true
		}
	}
	return sni, hasECH, nil
}

// parseSNIExtension extracts the hostname from an SNI extension value.
func parseSNIExtension(data []byte) string {
	// Server name list: length(2) then entries.
	if len(data) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < listLen {
		return ""
	}
	data = data[:listLen]

	for len(data) >= 3 {
		nameType := data[0]
		nameLen := int(binary.BigEndian.Uint16(data[1:3]))
		data = data[3:]
		if len(data) < nameLen {
			return ""
		}
		if nameType == tlsSNIHostNameType {
			return string(data[:nameLen])
		}
		data = data[nameLen:]
	}
	return ""
}

// handleTLSConnection reads up to 16KB from local to find a TLS ClientHello,
// inspects SNI/ECH, checks the domain against the filter, and either relays
// the connection or closes it.
func handleTLSConnection(local net.Conn, dst string, filter *FilterConfig) {
	defer func() { _ = local.Close() }()

	_ = local.SetReadDeadline(time.Now().Add(tlsReadTimeout))
	buf := make([]byte, tlsMaxRead)
	n, err := local.Read(buf)
	if err != nil || n == 0 {
		return
	}
	data := buf[:n]

	sni, hasECH, parseErr := ParseClientHello(data)

	// Block non-TLS traffic on port 443.
	if errors.Is(parseErr, errNotClientHello) {
		fmt.Fprintf(os.Stderr, "curb: tls blocked: non-TLS data on port 443 to %s\n", dst)
		return
	}
	// Truncated records: block (could be evasion).
	if errors.Is(parseErr, errTruncated) {
		fmt.Fprintf(os.Stderr, "curb: tls blocked: truncated ClientHello to %s\n", dst)
		return
	}

	// Block ECH if configured.
	if filter.BlockECH && hasECH {
		fmt.Fprintf(os.Stderr, "curb: tls blocked: ECH detected to %s\n", dst)
		return
	}

	// Require SNI if configured.
	if filter.RequireSNI && sni == "" {
		fmt.Fprintf(os.Stderr, "curb: tls blocked: no SNI to %s\n", dst)
		return
	}

	// Check domain allowlist.
	if sni != "" && !filter.Check(sni) {
		fmt.Fprintf(os.Stderr, "curb: tls blocked: %s\n", sni)
		return
	}

	// If no SNI and RequireSNI is false, allow (wildcard case).
	// If SNI is present and allowed, relay.

	// Clear deadline for relay.
	_ = local.SetReadDeadline(time.Time{})

	remote, dialErr := net.DialTimeout("tcp", dst, tcpDialTimeout)
	if dialErr != nil {
		fmt.Fprintf(os.Stderr, "curb: tls forward %s: %v\n", dst, dialErr)
		return
	}

	// Write the buffered data to the remote before relaying.
	if _, err := remote.Write(data); err != nil {
		fmt.Fprintf(os.Stderr, "curb: tls forward write %s: %v\n", dst, err)
		_ = remote.Close()
		return
	}

	relay(local, remote)
}
