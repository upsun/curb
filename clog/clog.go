// Package clog provides structured logging for curb.
// The name avoids shadowing the stdlib "log" package.
package clog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"golang.org/x/term"
)

// ANSI color sequences.
const (
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiDim    = "\033[2m"
	ansiReset  = "\033[0m"
)

// Logger writes structured events to a JSON log file and/or human-readable
// messages to stderr.
type Logger struct {
	json    *slog.Logger // JSON logger for --log-file (nil if unset).
	verbose bool         // --verbose: human-readable to stderr.
	debug   bool         // --debug: detailed proxy/relay logging to stderr.
	quiet   bool         // --quiet: suppress warnings.
	color   bool         // Whether stderr supports color.
	w       io.Writer    // Output writer (defaults to os.Stderr).
	file    *os.File     // Log file handle (nil if unset).

}

// New creates a Logger. If logFile is non-empty, JSON events are written to
// that file. If verbose is true, human-readable lines are written to stderr.
// If debug is true, detailed proxy/relay logging is enabled (implies verbose).
// If quiet is true, warnings are suppressed.
func New(logFile string, verbose, debug, quiet bool) (*Logger, error) {
	l := &Logger{
		verbose: verbose || debug,
		debug:   debug,
		quiet:   quiet,
		w:       os.Stderr,
	}
	l.color = isColorStderr()
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, fmt.Errorf("opening log file: %w", err)
		}
		l.file = f
		l.json = slog.New(slog.NewJSONHandler(f, nil))
	}
	return l, nil
}

// printLevel writes a prefixed message to stderr with optional color.
func (l *Logger) printLevel(prefix, color, msg string) {
	if l.color {
		_, _ = fmt.Fprintf(l.w, "%scurb: %s:%s %s\n", color, prefix, ansiReset, msg)
	} else {
		_, _ = fmt.Fprintf(l.w, "curb: %s: %s\n", prefix, msg)
	}
}

// Warn prints a warning to stderr, suppressed if quiet.
func (l *Logger) Warn(format string, args ...any) {
	if l == nil || l.quiet {
		return
	}
	l.printLevel("warning", ansiYellow, fmt.Sprintf(format, args...))
}

// Error prints an error to stderr, never suppressed.
func (l *Logger) Error(format string, args ...any) {
	if l == nil {
		return
	}
	l.printLevel("error", ansiRed, fmt.Sprintf(format, args...))
}

// Info prints an informational message to stderr, suppressed if quiet or not verbose.
func (l *Logger) Info(format string, args ...any) {
	if l == nil || l.quiet || !l.verbose {
		return
	}
	l.printLevel("info", ansiBlue, fmt.Sprintf(format, args...))
}

// Event logs a filtering event. Events are written to the JSON log file (if
// configured) and to stderr (if verbose mode is enabled).
// Parameters:
//
//	event  — event type (e.g. "dns_query", "tcp_connect", "http_request")
//	domain — the domain or destination involved
//	action — what happened ("allowed", "blocked")
//	reason — why (e.g. "domain", "port not allowed", empty if obvious)
func (l *Logger) Event(event, domain, action, reason string) {
	if l == nil {
		return
	}
	if l.json != nil {
		attrs := []slog.Attr{
			slog.String("event", event),
			slog.String("domain", domain),
			slog.String("action", action),
		}
		if reason != "" {
			attrs = append(attrs, slog.String("reason", reason))
		}
		l.json.LogAttrs(context.Background(), slog.LevelInfo, "", attrs...)
	}
	if l.verbose {
		var msg string
		if reason != "" {
			msg = fmt.Sprintf("%s %s: %s (%s)", event, action, domain, reason)
		} else {
			msg = fmt.Sprintf("%s %s: %s", event, action, domain)
		}
		if l.color {
			_, _ = fmt.Fprintf(l.w, "%scurb:%s %s\n", ansiDim, ansiReset, msg)
		} else {
			_, _ = fmt.Fprintf(l.w, "curb: %s\n", msg)
		}
	}
}

// IsDebug reports whether debug logging is enabled.
func (l *Logger) IsDebug() bool {
	return l != nil && l.debug
}

// Debug prints a debug message to stderr, only when --debug is enabled.
func (l *Logger) Debug(format string, args ...any) {
	if !l.IsDebug() {
		return
	}
	l.printLevel("debug", ansiDim, fmt.Sprintf(format, args...))
}

// Close closes the log file if open.
func (l *Logger) Close() {
	if l == nil {
		return
	}
	if l.file != nil {
		_ = l.file.Close()
	}
}

// Errorf prints a colored error to stderr without needing a Logger instance.
func Errorf(format string, args ...any) {
	l := &Logger{w: os.Stderr, color: isColorStderr()}
	l.printLevel("error", ansiRed, fmt.Sprintf(format, args...))
}

// Warnf prints a colored warning to stderr without needing a Logger instance.
// Unlike Logger.Warn, this does not honor --quiet. Callers must check quiet themselves.
func Warnf(format string, args ...any) {
	l := &Logger{w: os.Stderr, color: isColorStderr()}
	l.printLevel("warning", ansiYellow, fmt.Sprintf(format, args...))
}

// isColorStderr reports whether stderr supports color output.
func isColorStderr() bool {
	return term.IsTerminal(int(os.Stderr.Fd())) && os.Getenv("NO_COLOR") == ""
}
