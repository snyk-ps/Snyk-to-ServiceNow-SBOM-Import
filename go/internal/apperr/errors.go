// Package apperr defines typed application errors and stable process exit codes.
package apperr

import (
	"errors"
	"fmt"
	"strings"
)

const (
	ExitSuccess        = 0
	ExitConfig         = 1
	ExitAuth           = 2
	ExitSBOMGeneration = 3
	ExitUpload         = 4
	ExitUnexpected     = 5
)

// Kind identifies the failure category independently from its display text.
type Kind int

const (
	KindUnexpected Kind = iota
	KindConfig
	KindAuth
	KindSBOMGeneration
	KindUpload
	KindUnsupported
)

// Error carries structured, actionable context without embedding secrets.
type Error struct {
	Kind     Kind
	Message  string
	Op       string
	URL      string
	Status   int
	Detail   string
	NextStep string
	Cause    error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return "application error"
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// ExitCode returns the documented process exit code for the error.
func (e *Error) ExitCode() int {
	if e == nil {
		return ExitSuccess
	}
	switch e.Kind {
	case KindConfig:
		return ExitConfig
	case KindAuth:
		return ExitAuth
	case KindSBOMGeneration, KindUnsupported:
		return ExitSBOMGeneration
	case KindUpload:
		return ExitUpload
	default:
		return ExitUnexpected
	}
}

// Report formats the structured context as a multi-line, user-facing message.
func (e *Error) Report() string {
	if e == nil {
		return ""
	}
	lines := []string{e.Error()}
	if e.Op != "" {
		lines = append(lines, "  Operation: "+e.Op)
	}
	if e.URL != "" {
		lines = append(lines, "  URL: "+e.URL)
	}
	if e.Status != 0 {
		lines = append(lines, fmt.Sprintf("  HTTP Status: %d", e.Status))
	}
	if e.Detail != "" {
		lines = append(lines, "  Detail: "+e.Detail)
	}
	if e.NextStep != "" {
		lines = append(lines, "  Next step: "+e.NextStep)
	}
	return strings.Join(lines, "\n")
}

// ExitCode extracts an application exit code, defaulting to unexpected.
func ExitCode(err error) int {
	if err == nil {
		return ExitSuccess
	}
	var appErr *Error
	if errors.As(err, &appErr) {
		return appErr.ExitCode()
	}
	return ExitUnexpected
}

// IsKind reports whether err (or a wrapped error) has the requested kind.
func IsKind(err error, kind Kind) bool {
	var appErr *Error
	return errors.As(err, &appErr) && appErr.Kind == kind
}

// IsUnsupported reports whether the Snyk project does not support SBOM export.
func IsUnsupported(err error) bool {
	return IsKind(err, KindUnsupported)
}
