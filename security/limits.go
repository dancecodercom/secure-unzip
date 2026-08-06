package security

import "fmt"

// Profile defaults for --secure=yes. See
// docs/agents/decisions/2026-08-06-secure-master-switch.md.
const (
	DefaultMaxSize  int64 = 10737418240 // 10 GiB
	DefaultMaxFiles int64 = 10000
	DefaultMaxRatio int64 = 100 // uncompressed:compressed expansion ceiling
)

// Limits is the resolved set of resource ceilings for one run. A zero value
// for any field means "unlimited" — that is how --secure=no is expressed.
type Limits struct {
	MaxSize  int64
	MaxFiles int64
	MaxRatio int64
}

// SecureLimits returns the --secure=yes profile.
func SecureLimits() Limits {
	return Limits{
		MaxSize:  DefaultMaxSize,
		MaxFiles: DefaultMaxFiles,
		MaxRatio: DefaultMaxRatio,
	}
}

// UnsecureLimits returns the --secure=no profile: every ceiling lifted.
func UnsecureLimits() Limits { return Limits{} }

// Budget tracks consumption against Limits over the course of one extraction.
// It is not safe for concurrent use; extraction is single-streamed.
type Budget struct {
	limits Limits

	Files       int64 // files and directories created
	Directories int64
	Bytes       int64 // uncompressed bytes written
	Compressed  int64 // compressed bytes read, for the ratio check
}

func NewBudget(l Limits) *Budget { return &Budget{limits: l} }

// AddFile counts one entry against MaxFiles.
func (b *Budget) AddFile(entry string) error {
	b.Files++
	if b.limits.MaxFiles > 0 && b.Files > b.limits.MaxFiles {
		return newConstraintError(ConstraintMaxFiles, entry,
			"archive contains more than %d entries", b.limits.MaxFiles)
	}
	return nil
}

// AddDirectory counts a directory. Directories consume inodes too, so they
// count against MaxFiles exactly like regular files.
func (b *Budget) AddDirectory(entry string) error {
	b.Directories++
	return b.AddFile(entry)
}

// AddBytes counts n uncompressed bytes. It is called from the streaming reader
// on every read, so a bomb is stopped while expanding rather than afterwards.
func (b *Budget) AddBytes(entry string, n int64) error {
	b.Bytes += n
	if b.limits.MaxSize > 0 && b.Bytes > b.limits.MaxSize {
		return newConstraintError(ConstraintMaxSize, entry,
			"total uncompressed size exceeds %s limit", HumanBytes(b.limits.MaxSize))
	}
	return nil
}

// AddCompressed records compressed bytes consumed, for the ratio check.
func (b *Budget) AddCompressed(n int64) { b.Compressed += n }

// CheckDeclaredSize is an early-out using the archive's declared sizes. The
// header is attacker-controlled and may understate the real size, so this can
// only ever reject early — it can never certify an entry as safe. AddBytes is
// the control that actually holds.
func (b *Budget) CheckDeclaredSize(entry string, declared int64) error {
	if b.limits.MaxSize > 0 && declared > 0 && b.Bytes+declared > b.limits.MaxSize {
		return newConstraintError(ConstraintMaxSize, entry,
			"declared uncompressed size would exceed %s limit", HumanBytes(b.limits.MaxSize))
	}
	return nil
}

// CheckRatio enforces the expansion ceiling. Small entries are exempt: a few
// hundred bytes of zeros trivially exceeds any ratio and means nothing.
const ratioFloorBytes = 1 << 20 // 1 MiB

func (b *Budget) CheckRatio(entry string, uncompressed, compressed int64) error {
	if b.limits.MaxRatio <= 0 || uncompressed < ratioFloorBytes || compressed <= 0 {
		return nil
	}
	if ratio := uncompressed / compressed; ratio > b.limits.MaxRatio {
		return newConstraintError(ConstraintMaxRatio, entry,
			"compression ratio %d:1 exceeds the %d:1 ceiling", ratio, b.limits.MaxRatio)
	}
	return nil
}

// HumanBytes formats a byte count in binary units for error messages.
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
