//go:build linux

package netstack

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildClientHello constructs a minimal TLS 1.2 ClientHello with optional extensions.
func buildClientHello(extensions []byte) []byte {
	// ClientHello body: version(2) + random(32) + session_id(1+0) + cipher_suites(2+2) + compression(1+1).
	body := make([]byte, 0, 128)
	body = append(body, 0x03, 0x03) // TLS 1.2
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)       // Session ID length = 0.
	body = append(body, 0x00, 0x02) // Cipher suites length = 2.
	body = append(body, 0x00, 0x2f) // TLS_RSA_WITH_AES_128_CBC_SHA.
	body = append(body, 0x01)       // Compression methods length = 1.
	body = append(body, 0x00)       // No compression.
	if len(extensions) > 0 {
		body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
		body = append(body, extensions...)
	}

	// Handshake header: type(1) + length(3).
	hs := []byte{0x01}
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	// TLS record header: content_type(1) + version(2) + length(2).
	record := []byte{0x16, 0x03, 0x01}
	record = binary.BigEndian.AppendUint16(record, uint16(len(hs)))
	record = append(record, hs...)
	return record
}

// buildSNIExtension constructs an SNI extension for the given hostname.
func buildSNIExtension(hostname string) []byte {
	nameBytes := []byte(hostname)
	// SNI entry: type(1) + name_length(2) + name.
	entry := []byte{0x00} // Host name type.
	entry = binary.BigEndian.AppendUint16(entry, uint16(len(nameBytes)))
	entry = append(entry, nameBytes...)
	// Server name list: length(2) + entries.
	snList := binary.BigEndian.AppendUint16(nil, uint16(len(entry)))
	snList = append(snList, entry...)
	// Extension: type(2) + length(2) + data.
	ext := binary.BigEndian.AppendUint16(nil, tlsExtSNI)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(snList)))
	ext = append(ext, snList...)
	return ext
}

// buildECHExtension constructs a minimal ECH extension.
func buildECHExtension() []byte {
	echData := []byte{0x00, 0x01, 0x00, 0x01, 0x00} // Dummy ECH payload.
	ext := binary.BigEndian.AppendUint16(nil, tlsExtECH)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(echData)))
	ext = append(ext, echData...)
	return ext
}

func TestParseClientHello_ValidSNI(t *testing.T) {
	exts := buildSNIExtension("example.com")
	data := buildClientHello(exts)

	sni, hasECH, err := ParseClientHello(data)
	require.NoError(t, err)
	assert.Equal(t, "example.com", sni)
	assert.False(t, hasECH)
}

func TestParseClientHello_NoSNI(t *testing.T) {
	data := buildClientHello(nil)

	sni, hasECH, err := ParseClientHello(data)
	require.NoError(t, err)
	assert.Empty(t, sni)
	assert.False(t, hasECH)
}

func TestParseClientHello_ECHOnly(t *testing.T) {
	exts := buildECHExtension()
	data := buildClientHello(exts)

	sni, hasECH, err := ParseClientHello(data)
	require.NoError(t, err)
	assert.Empty(t, sni)
	assert.True(t, hasECH)
}

func TestParseClientHello_SNIAndECH(t *testing.T) {
	exts := append(buildSNIExtension("example.com"), buildECHExtension()...)
	data := buildClientHello(exts)

	sni, hasECH, err := ParseClientHello(data)
	require.NoError(t, err)
	assert.Equal(t, "example.com", sni)
	assert.True(t, hasECH)
}

func TestParseClientHello_NonTLSData(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	_, _, err := ParseClientHello(data)
	assert.ErrorIs(t, err, errNotClientHello)
}

func TestParseClientHello_Truncated(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"short header", []byte{0x16, 0x03}},
		{"record length exceeds data", []byte{0x16, 0x03, 0x01, 0x00, 0x10, 0x01}},
		{"handshake length exceeds data", func() []byte {
			// Valid record header, but handshake length exceeds payload.
			return []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 0x00, 0x00}
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseClientHello(tt.data)
			assert.Error(t, err)
		})
	}
}

func TestParseClientHello_WrongHandshakeType(t *testing.T) {
	// Build a valid TLS record but with ServerHello type (0x02).
	body := make([]byte, 38) // version(2) + random(32) + session_id(1+0) + cipher(2) + compression(1).
	body[0] = 0x03
	body[1] = 0x03
	body[34] = 0x00
	body[35] = 0x00
	body[36] = 0x2f
	body[37] = 0x00

	hs := []byte{0x02} // ServerHello type.
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	record := []byte{0x16, 0x03, 0x01}
	record = binary.BigEndian.AppendUint16(record, uint16(len(hs)))
	record = append(record, hs...)

	_, _, err := ParseClientHello(record)
	assert.ErrorIs(t, err, errNotClientHello)
}

func TestParseClientHello_MalformedExtensionLength(t *testing.T) {
	// Extension that claims more data than available.
	ext := binary.BigEndian.AppendUint16(nil, tlsExtSNI)
	ext = binary.BigEndian.AppendUint16(ext, 0x00FF) // Claims 255 bytes.
	ext = append(ext, 0x00)                          // Only 1 byte.
	data := buildClientHello(ext)
	// The extensions total length in the ClientHello will be len(ext) = 5,
	// but the extension header says 255, so parsing should fail.
	_, _, err := ParseClientHello(data)
	assert.ErrorIs(t, err, errTruncated)
}

func TestParseClientHello_EmptySNIList(t *testing.T) {
	// SNI extension with an empty server name list.
	snList := binary.BigEndian.AppendUint16(nil, 0) // List length = 0.
	ext := binary.BigEndian.AppendUint16(nil, tlsExtSNI)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(snList)))
	ext = append(ext, snList...)
	data := buildClientHello(ext)

	sni, _, err := ParseClientHello(data)
	require.NoError(t, err)
	assert.Empty(t, sni, "empty SNI list should yield no hostname")
}

func TestParseClientHello_MultipleExtensions(t *testing.T) {
	// An unknown extension followed by SNI.
	unknown := binary.BigEndian.AppendUint16(nil, 0x0017) // Extended master secret.
	unknown = binary.BigEndian.AppendUint16(unknown, 0)   // Length = 0.
	exts := append(unknown, buildSNIExtension("test.example.org")...)
	data := buildClientHello(exts)

	sni, _, err := ParseClientHello(data)
	require.NoError(t, err)
	assert.Equal(t, "test.example.org", sni)
}

func TestHandleTLSConnection_ECHDeny(t *testing.T) {
	exts := append(buildSNIExtension("example.com"), buildECHExtension()...)
	data := buildClientHello(exts)

	client, server := net.Pipe()
	filter := &FilterConfig{
		Check:   func(string) bool { return true },
		ECHMode: ECHDeny,
	}

	done := make(chan struct{})
	go func() {
		handleTLSConnection(server, "93.184.216.34:443", filter)
		close(done)
	}()

	_, _ = client.Write(data)
	// The handler should close the connection since ECH is denied.
	buf := make([]byte, 1)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, err := client.Read(buf)
	assert.Error(t, err, "connection should be closed when ECH is denied")
	_ = client.Close()
	<-done
}

func TestHandleTLSConnection_ECHAllow(t *testing.T) {
	exts := append(buildSNIExtension("example.com"), buildECHExtension()...)
	data := buildClientHello(exts)

	client, server := net.Pipe()
	filter := &FilterConfig{
		Check:   func(string) bool { return true },
		ECHMode: ECHAllow,
	}

	done := make(chan struct{})
	go func() {
		// This will try to dial 127.0.0.1:1 which will fail, but it means
		// ECH was not blocked (it proceeded past the ECH check).
		handleTLSConnection(server, "127.0.0.1:1", filter)
		close(done)
	}()

	_, _ = client.Write(data)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	_, err := client.Read(buf)
	assert.Error(t, err, "connection should close after dial failure")
	_ = client.Close()
	<-done
}

func TestHandleTLSConnection_ECHStripWithValidIP(t *testing.T) {
	exts := append(buildSNIExtension("example.com"), buildECHExtension()...)
	data := buildClientHello(exts)

	client, server := net.Pipe()
	filter := &FilterConfig{
		Check:   func(string) bool { return true },
		ECHMode: ECHStrip,
		checkIP: func(ip string) bool { return ip == "93.184.216.34" },
	}

	done := make(chan struct{})
	go func() {
		handleTLSConnection(server, "93.184.216.34:443", filter)
		close(done)
	}()

	_, _ = client.Write(data)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	_, _ = client.Read(buf)
	_ = client.Close()
	<-done
}

func TestHandleTLSConnection_ECHStripWithUnknownIP(t *testing.T) {
	exts := append(buildSNIExtension("example.com"), buildECHExtension()...)
	data := buildClientHello(exts)

	client, server := net.Pipe()
	filter := &FilterConfig{
		Check:   func(string) bool { return true },
		ECHMode: ECHStrip,
		checkIP: func(string) bool { return false },
	}

	done := make(chan struct{})
	go func() {
		handleTLSConnection(server, "1.2.3.4:443", filter)
		close(done)
	}()

	_, _ = client.Write(data)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	_, err := client.Read(buf)
	assert.Error(t, err, "connection should be closed when ECH strip has unknown IP")
	_ = client.Close()
	<-done
}

func TestHandleTLSConnection_BlockedSNI(t *testing.T) {
	exts := buildSNIExtension("blocked.com")
	data := buildClientHello(exts)

	client, server := net.Pipe()
	filter := &FilterConfig{
		Check: func(domain string) bool { return domain != "blocked.com" },
	}

	done := make(chan struct{})
	go func() {
		handleTLSConnection(server, "93.184.216.34:443", filter)
		close(done)
	}()

	_, _ = client.Write(data)
	buf := make([]byte, 1)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, err := client.Read(buf)
	assert.Error(t, err, "connection should be closed for blocked SNI")
	_ = client.Close()
	<-done
}

func TestHandleTLSConnection_NoSNI_RequireSNI(t *testing.T) {
	data := buildClientHello(nil) // No extensions, no SNI.

	client, server := net.Pipe()
	filter := &FilterConfig{
		Check:      func(string) bool { return true },
		RequireSNI: true,
	}

	done := make(chan struct{})
	go func() {
		handleTLSConnection(server, "93.184.216.34:443", filter)
		close(done)
	}()

	_, _ = client.Write(data)
	buf := make([]byte, 1)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, err := client.Read(buf)
	assert.Error(t, err, "connection should be closed when RequireSNI and no SNI")
	_ = client.Close()
	<-done
}

func TestHandleTLSConnection_NonTLSData(t *testing.T) {
	client, server := net.Pipe()
	filter := &FilterConfig{
		Check: func(string) bool { return true },
	}

	done := make(chan struct{})
	go func() {
		handleTLSConnection(server, "93.184.216.34:443", filter)
		close(done)
	}()

	_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	buf := make([]byte, 1)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, err := client.Read(buf)
	assert.Error(t, err, "connection should be closed for non-TLS data on 443")
	_ = client.Close()
	<-done
}

func TestHandleTLSConnection_TruncatedRecord(t *testing.T) {
	// TLS record header claiming more data than provided.
	data := []byte{0x16, 0x03, 0x01, 0x00, 0x10, 0x01}

	client, server := net.Pipe()
	filter := &FilterConfig{
		Check: func(string) bool { return true },
	}

	done := make(chan struct{})
	go func() {
		handleTLSConnection(server, "93.184.216.34:443", filter)
		close(done)
	}()

	_, _ = client.Write(data)
	buf := make([]byte, 1)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, err := client.Read(buf)
	assert.Error(t, err, "connection should be closed for truncated TLS record")
	_ = client.Close()
	<-done
}

func TestHandleTLSConnection_AllowedSNI(t *testing.T) {
	exts := buildSNIExtension("allowed.com")
	data := buildClientHello(exts)

	client, server := net.Pipe()
	filter := &FilterConfig{
		Check: func(string) bool { return true },
	}

	done := make(chan struct{})
	go func() {
		// Dial will fail (no real server), but the handler should not block the SNI.
		handleTLSConnection(server, "127.0.0.1:1", filter)
		close(done)
	}()

	_, _ = client.Write(data)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	_, _ = client.Read(buf)
	// Connection closes after dial failure, not from filtering.
	_ = client.Close()
	<-done
}

func TestHandleTLSConnection_ECHStripNilCheckIP(t *testing.T) {
	exts := append(buildSNIExtension("example.com"), buildECHExtension()...)
	data := buildClientHello(exts)

	client, server := net.Pipe()
	filter := &FilterConfig{
		Check:   func(string) bool { return true },
		ECHMode: ECHStrip,
	}

	done := make(chan struct{})
	go func() {
		handleTLSConnection(server, "1.2.3.4:443", filter)
		close(done)
	}()

	_, _ = client.Write(data)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	_, err := client.Read(buf)
	assert.Error(t, err, "connection should be closed when checkIP is nil")
	_ = client.Close()
	<-done
}
