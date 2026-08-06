// Package security holds the extraction safety controls. It decides; it never
// writes to the filesystem. That separation is what makes every control here
// unit-testable without a disk.
package security

import (
	"errors"
	"fmt"
)

// Constraint names. These strings appear verbatim in error messages and the
// end-to-end tests assert on them: treat them as part of the contract.
const (
	ConstraintZipSlip       = "zip-slip"
	ConstraintSymlinkEscape = "symlink-escape"
	ConstraintMaxSize       = "max-size"
	ConstraintMaxRatio      = "max-ratio"
	ConstraintMaxFiles      = "max-files"
	ConstraintMaxMode       = "max-mode"
)

// ConstraintError reports that a security constraint was breached. Every such
// error names its constraint (CLAUDE.md §5) and maps to exit code 3.
type ConstraintError struct {
	Constraint string // one of the Constraint* values
	Entry      string // archive entry that triggered it, if any
	Detail     string
}

func (e *ConstraintError) Error() string {
	if e.Entry != "" {
		return fmt.Sprintf("security constraint %s violated by entry %q: %s",
			e.Constraint, e.Entry, e.Detail)
	}
	return fmt.Sprintf("security constraint %s violated: %s", e.Constraint, e.Detail)
}

func newConstraintError(constraint, entry, format string, args ...any) *ConstraintError {
	return &ConstraintError{
		Constraint: constraint,
		Entry:      entry,
		Detail:     fmt.Sprintf(format, args...),
	}
}

// AsConstraintError extracts a *ConstraintError from err, if present.
func AsConstraintError(err error) (*ConstraintError, bool) {
	var ce *ConstraintError
	if errors.As(err, &ce) {
		return ce, true
	}
	return nil, false
}

// IsConstraintError reports whether err is (or wraps) a ConstraintError.
func IsConstraintError(err error) bool {
	_, ok := AsConstraintError(err)
	return ok
}
