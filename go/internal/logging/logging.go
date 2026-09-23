// Package logging provides the timestamped, leveled logger used by the CLI.
package logging

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Level values are ordered from most verbose to least verbose.
type Level int

const (
	Trace Level = iota
	Debug
	Info
	Warning
	Error
)

// ParseLevel resolves a case-insensitive level name, defaulting to INFO.
func ParseLevel(value string) Level {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "TRACE":
		return Trace
	case "DEBUG":
		return Debug
	case "WARNING", "WARN":
		return Warning
	case "ERROR":
		return Error
	default:
		return Info
	}
}

// Logger writes stable, human-readable log lines.
type Logger struct {
	mu    sync.Mutex
	out   io.Writer
	level Level
	now   func() time.Time
}

// New creates a logger. A nil writer defaults to stderr.
func New(level string, out io.Writer) *Logger {
	if out == nil {
		out = os.Stderr
	}
	return &Logger{
		out:   out,
		level: ParseLevel(level),
		now:   time.Now,
	}
}

// Enabled reports whether a level would be emitted.
func (l *Logger) Enabled(level Level) bool {
	return l != nil && level >= l.level
}

func (l *Logger) log(level Level, label, format string, args ...any) {
	if !l.Enabled(level) {
		return
	}
	message := fmt.Sprintf(format, args...)
	timestamp := l.now().Format("2006-01-02 15:04:05")
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.out, "%s | %-7s | %s\n", timestamp, label, message)
}

func (l *Logger) Trace(format string, args ...any) {
	l.log(Trace, "TRACE", format, args...)
}

func (l *Logger) Debug(format string, args ...any) {
	l.log(Debug, "DEBUG", format, args...)
}

func (l *Logger) Info(format string, args ...any) {
	l.log(Info, "INFO", format, args...)
}

func (l *Logger) Warn(format string, args ...any) {
	l.log(Warning, "WARNING", format, args...)
}

func (l *Logger) Error(format string, args ...any) {
	l.log(Error, "ERROR", format, args...)
}
