package extractor

import (
	"io/fs"
	"os"
)

// chmodIfSupported applies a mode, tolerating platforms that cannot represent it.
//
// On Windows, Go's os.Chmod honours only the owner-write bit (it toggles the
// read-only attribute); the rest of the POSIX bits have no meaning there. That
// is still exactly what -read-only needs, so the call is worth making on every
// platform — but a failure to set permissions must not fail an otherwise good
// extraction on a filesystem that does not support them (FAT, some network
// mounts), so ErrUnsupported and permission errors are ignored.
func chmodIfSupported(path string, mode fs.FileMode) error {
	err := os.Chmod(path, mode.Perm())
	if err == nil || os.IsPermission(err) {
		return nil
	}
	if pathErr, ok := err.(*os.PathError); ok {
		if pathErr.Err == os.ErrInvalid {
			return nil
		}
	}
	return err
}
