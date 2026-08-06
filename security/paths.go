package security

import (
	"path"
	"path/filepath"
	"strings"
)

// ResolveRoot canonicalises the destination directory so it can serve as the
// containment root. It must be called once per archive, before any entry is
// checked: every later containment assertion is relative to this value.
//
// The directory must already exist. EvalSymlinks matters — if the destination
// is itself a symlink, comparing against the unresolved path would compare two
// different namespaces and the prefix check would be meaningless.
func ResolveRoot(dest string) (string, error) {
	abs, err := filepath.Abs(dest)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// Destination does not exist yet: the caller creates it and retries.
		return filepath.Clean(abs), err
	}
	return filepath.Clean(resolved), nil
}

// SafeJoin maps an archive entry name to an absolute path underneath root, or
// returns a ConstraintError if the entry tries to escape (Zip Slip).
//
// Order matters. The name is rejected on its own terms first, and only then
// joined — a check performed after joining can be defeated by a name that
// Clean collapses into something innocuous.
func SafeJoin(root, entryName string) (string, error) {
	name := entryName

	// Zip entry names are defined to use forward slashes. A backslash is a
	// legal filename byte on POSIX but a separator on Windows, so a name like
	// `..\..\x` escapes on Windows while looking harmless to a POSIX-only
	// check. Normalise before deciding anything.
	name = strings.ReplaceAll(name, `\`, "/")

	if name == "" {
		return "", newConstraintError(ConstraintZipSlip, entryName, "empty entry name")
	}
	if strings.ContainsRune(name, 0) {
		return "", newConstraintError(ConstraintZipSlip, entryName, "entry name contains a NUL byte")
	}

	// Absolute paths, POSIX or Windows drive-letter form (`C:/x`, `//host/share`).
	if strings.HasPrefix(name, "/") || hasDriveLetter(name) {
		return "", newConstraintError(ConstraintZipSlip, entryName,
			"absolute path in archive entry")
	}

	// Reject traversal on the raw components, before any cleaning collapses them.
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", newConstraintError(ConstraintZipSlip, entryName,
				"parent directory traversal (%q) in archive entry", "..")
		}
	}

	cleaned := path.Clean(name)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", newConstraintError(ConstraintZipSlip, entryName,
			"entry resolves outside the destination")
	}

	target := filepath.Join(root, filepath.FromSlash(cleaned))

	// Belt and braces: the assertions above should make this unreachable, but
	// this is the invariant that actually matters, so assert it directly.
	if !Contains(root, target) {
		return "", newConstraintError(ConstraintZipSlip, entryName,
			"entry resolves outside the destination directory")
	}
	return target, nil
}

// Contains reports whether target lies within root. Both must be cleaned
// absolute paths. root itself does not count as being contained.
func Contains(root, target string) bool {
	if root == target {
		return false
	}
	prefix := root
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	return strings.HasPrefix(target, prefix)
}

// CheckSymlinkTarget validates a symlink entry before it is created.
// linkPath is the absolute path the link will occupy; target is the raw link
// text from the archive. The link may only point at something inside root.
//
// This is the subtlest control in the package. A symlink is a second, deferred
// chance to escape the destination: the link itself passes SafeJoin, but the
// path it names does not have to.
func CheckSymlinkTarget(root, linkPath, target string) error {
	if target == "" {
		return newConstraintError(ConstraintSymlinkEscape, linkPath, "empty symlink target")
	}

	normalised := strings.ReplaceAll(target, `\`, "/")

	if strings.HasPrefix(normalised, "/") || hasDriveLetter(normalised) {
		return newConstraintError(ConstraintSymlinkEscape, linkPath,
			"symlink points at an absolute path (%q)", target)
	}

	// Resolve the target relative to the directory holding the link, exactly
	// as the kernel would, then require the result to stay inside root.
	resolved := filepath.Clean(
		filepath.Join(filepath.Dir(linkPath), filepath.FromSlash(normalised)),
	)
	if !Contains(root, resolved) {
		return newConstraintError(ConstraintSymlinkEscape, linkPath,
			"symlink target %q resolves to %q, outside the destination", target, resolved)
	}
	return nil
}

// hasDriveLetter matches Windows absolute forms: `C:/…`, `C:…`, and UNC `//host/share`.
func hasDriveLetter(name string) bool {
	if strings.HasPrefix(name, "//") {
		return true
	}
	if len(name) >= 2 && name[1] == ':' {
		c := name[0]
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	return false
}
