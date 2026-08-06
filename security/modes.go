package security

import "io/fs"

// DefaultMaxMode is the --secure=yes permission ceiling: no setuid/setgid/
// sticky, no group or other write, but the executable bit survives so that
// extracted scripts and binaries still run.
const DefaultMaxMode fs.FileMode = 0o755

// dangerousBits are stripped unconditionally whenever masking is active. A
// setuid binary arriving from an untrusted archive is the classic privilege
// escalation, and no sane ceiling permits it.
const dangerousBits = fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky

// MaskMode reduces an archive entry's mode to fit under maxMode. A maxMode of
// 0 means masking is off (--secure=no) and the entry mode is returned as-is,
// except that the dangerous bits are still cleared: those are never legitimate
// in an extracted archive, whatever the profile.
func MaskMode(entryMode, maxMode fs.FileMode) fs.FileMode {
	mode := entryMode &^ dangerousBits
	if maxMode == 0 {
		return mode
	}
	perm := mode.Perm() & maxMode.Perm()
	if perm&0o400 == 0 {
		// An entry we cannot read back is useless; guarantee owner-read.
		perm |= 0o400
	}
	return (mode &^ fs.ModePerm) | perm
}

// ReadOnlyMode returns the mode a file should carry once -read-only has been
// applied: every write bit stripped, everything else left alone. Read and
// execute bits are preserved, so 0755 becomes 0555 and 0644 becomes 0444.
//
// This is applied AFTER the file's data is written. Creating the file
// read-only and then writing to it fails — see
// docs/agents/decisions/2026-08-06-write-then-lock-readonly.md.
func ReadOnlyMode(m fs.FileMode) fs.FileMode {
	perm := m.Perm() &^ 0o222 // clear all write bits
	if perm&0o400 == 0 {
		// Never produce a file its owner cannot read back.
		perm |= 0o400
	}
	return (m &^ fs.ModePerm) | perm
}

// DirMode adapts a mode for a directory: a directory that is not executable
// cannot be traversed, so owner-execute is always required while the file is
// being populated. The read-only lock is applied to directories last of all.
func DirMode(m fs.FileMode) fs.FileMode {
	return m | 0o700
}
