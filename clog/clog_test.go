package clog

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLogger(quiet bool) (*Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	l := &Logger{
		verbose: true,
		quiet:   quiet,
		color:   false, // Pipes disable color automatically.
		w:       &buf,
	}
	return l, &buf
}

func TestWarn(t *testing.T) {
	l, buf := newTestLogger(false)
	l.Warn("Something happened (%s).", "reason")
	assert.Equal(t, "curb: warning: Something happened (reason).\n", buf.String())
}

func TestWarn_Quiet(t *testing.T) {
	l, buf := newTestLogger(true)
	l.Warn("Should not appear.")
	assert.Empty(t, buf.String())
}

func TestError(t *testing.T) {
	l, buf := newTestLogger(false)
	l.Error("Failed to do %s.", "thing")
	assert.Equal(t, "curb: error: Failed to do thing.\n", buf.String())
}

func TestError_NotSuppressedByQuiet(t *testing.T) {
	l, buf := newTestLogger(true)
	l.Error("Still visible.")
	assert.Equal(t, "curb: error: Still visible.\n", buf.String())
}

func TestInfo(t *testing.T) {
	l, buf := newTestLogger(false)
	l.Info("Detail: %d.", 42)
	assert.Equal(t, "curb: info: Detail: 42.\n", buf.String())
}

func TestInfo_Quiet(t *testing.T) {
	l, buf := newTestLogger(true)
	l.Info("Should not appear.")
	assert.Empty(t, buf.String())
}

func TestInfo_NotVerbose(t *testing.T) {
	l, buf := newTestLogger(false)
	l.verbose = false
	l.Info("Should not appear.")
	assert.Empty(t, buf.String())
}

func TestEvent(t *testing.T) {
	l, buf := newTestLogger(false)
	l.Event("dns_query", "example.com", "allowed", "")
	assert.Equal(t, "curb: dns_query allowed: example.com\n", buf.String())
}

func TestEvent_WithReason(t *testing.T) {
	l, buf := newTestLogger(false)
	l.Event("tcp_connect", "evil.com", "blocked", "domain")
	assert.Equal(t, "curb: tcp_connect blocked: evil.com (domain)\n", buf.String())
}

func TestNilSafety(t *testing.T) {
	var l *Logger
	require.NotPanics(t, func() {
		l.Warn("noop")
		l.Error("noop")
		l.Info("noop")
		l.Debug("noop")
		l.Event("test", "test", "test", "")
		l.Close()
	})
}

func TestNew(t *testing.T) {
	l, err := New("", false, false, false)
	require.NoError(t, err)
	defer l.Close()
	assert.NotNil(t, l)
}

func TestNew_WithLogFile(t *testing.T) {
	dir := t.TempDir()
	logPath := dir + "/test.log"

	l, err := New(logPath, true, false, false)
	require.NoError(t, err)

	l.Event("dns_query", "example.com", "allowed", "")
	l.Event("tcp_connect", "blocked.com", "blocked", "domain")
	l.Close()

	data, err := os.ReadFile(logPath)
	require.NoError(t, err)
	s := string(data)
	assert.Contains(t, s, `"event":"dns_query"`)
	assert.Contains(t, s, `"action":"allowed"`)
	assert.Contains(t, s, `"event":"tcp_connect"`)
	assert.Contains(t, s, `"reason":"domain"`)
	// First event has no reason, so no "reason" key in that line.
	lines := strings.Split(strings.TrimSpace(s), "\n")
	require.Len(t, lines, 2)
	assert.NotContains(t, lines[0], `"reason"`)
}

func TestNew_InvalidLogFile(t *testing.T) {
	_, err := New("/nonexistent/directory/logfile.json", false, false, false)
	require.Error(t, err)
}
