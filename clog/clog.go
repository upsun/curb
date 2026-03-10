// Package clog provides structured logging for curb.
// The name avoids shadowing the stdlib "log" package.
package clog

import (
	"context"
	"fmt"
	"log/slog"
	"os"
)

// Logger writes structured events to a JSON log file and/or human-readable
// messages to stderr.
type Logger struct {
	json    *slog.Logger // JSON logger for --log-file (nil if unset).
	verbose bool         // --verbose: human-readable to stderr.
	file    *os.File     // Log file handle (nil if unset).
}

// New creates a Logger. If logFile is non-empty, JSON events are written to
// that file. If verbose is true, human-readable lines are written to stderr.
func New(logFile string, verbose bool) (*Logger, error) {
	l := &Logger{verbose: verbose}
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

// Event logs a filtering event. Events are written to the JSON log file (if
// configured) and to stderr (if verbose mode is enabled).
// Parameters:
//
//	event  — event type (e.g. "dns_query", "tls_connect", "http_request")
//	domain — the domain or destination involved
//	action — what happened ("allowed", "blocked")
//	reason — why (e.g. "ech", "no_sni", "domain", empty if obvious)
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
		if reason != "" {
			fmt.Fprintf(os.Stderr, "curb: %s %s: %s (%s)\n", event, action, domain, reason)
		} else {
			fmt.Fprintf(os.Stderr, "curb: %s %s: %s\n", event, action, domain)
		}
	}
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

