// Package extractor opens archives and writes their contents to disk. Every
// decision about whether something may be written belongs to the security
// package; this package acts on those decisions in a fixed order.
package extractor

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/pforret/secure-unzip/security"
)

// Options is the resolved configuration for one extraction.
type Options struct {
	Dest      string
	Limits    security.Limits
	MaxMode   fs.FileMode // 0 disables permission masking
	ReadOnly  bool
	Overwrite bool
	Quiet     bool

	// AllowUnsafePaths disables zip-slip containment and symlink target
	// checking — the --secure=no behaviour. It also disables staging, since a
	// deliberately escaping entry cannot be staged and then moved into place.
	// Extraction then writes directly to the destination and can leave partial
	// output behind, exactly like standard unzip.
	AllowUnsafePaths bool

	// Log receives per-entry progress lines. Nil discards them.
	Log func(format string, args ...any)
}

// Result reports what an extraction did, for --verbose and the exit code.
type Result struct {
	Files       int64
	Directories int64
	Symlinks    int64
	Bytes       int64
	Duration    time.Duration
	Warnings    []string

	// createdDirs holds the archive-relative paths of directories this run
	// created, so -read-only locks only those and leaves any pre-existing
	// directories in the destination alone.
	createdDirs []string
}

// Extract unpacks archivePath into opts.Dest.
//
// Nothing is written to the destination until the whole archive has been
// extracted successfully: entries land in a sibling temp directory first and
// are moved into place at the end. An abort therefore leaves the destination
// exactly as it was.
func Extract(archivePath string, opts Options) (*Result, error) {
	start := time.Now()

	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, fmt.Errorf("cannot open archive %s: %w", archivePath, err)
	}
	defer zr.Close()

	if err := os.MkdirAll(opts.Dest, 0o755); err != nil {
		return nil, fmt.Errorf("cannot create destination %s: %w", opts.Dest, err)
	}
	dest, err := security.ResolveRoot(opts.Dest)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve destination %s: %w", opts.Dest, err)
	}

	// Under --secure=no there is no staging: an entry that deliberately escapes
	// the destination cannot be staged and then moved into place, so unsafe
	// mode writes directly and may leave partial output, like unzip does.
	writeRoot := dest
	stage := ""
	committed := true

	if !opts.AllowUnsafePaths {
		// The staging directory is a SIBLING of the destination, not in TMPDIR,
		// so the final move is a same-filesystem rename rather than a copy.
		stage, err = os.MkdirTemp(filepath.Dir(dest), ".secure-unzip-*")
		if err != nil {
			return nil, fmt.Errorf("cannot create staging directory: %w", err)
		}
		committed = false
		defer func() {
			if !committed {
				os.RemoveAll(stage)
			}
		}()
		if writeRoot, err = security.ResolveRoot(stage); err != nil {
			return nil, fmt.Errorf("cannot resolve staging directory: %w", err)
		}
	}

	res := &Result{}
	budget := security.NewBudget(opts.Limits)

	for _, f := range zr.File {
		if err := extractEntry(f, writeRoot, budget, &opts, res); err != nil {
			res.Duration = time.Since(start)
			return res, err
		}
	}

	if stage != "" {
		if err := commit(writeRoot, dest, opts.Overwrite); err != nil {
			res.Duration = time.Since(start)
			return res, err
		}
		committed = true
		os.RemoveAll(stage)
	}

	// Directories are locked last of all, and only after the commit: a
	// directory cannot be written into while read-only, and on POSIX it cannot
	// even be renamed, since the move rewrites its ".." entry.
	if opts.ReadOnly {
		if err := lockDirectories(dest, res.createdDirs); err != nil {
			res.Duration = time.Since(start)
			return res, err
		}
	}

	res.Files = budget.Files - budget.Directories
	res.Directories = budget.Directories
	res.Bytes = budget.Bytes
	res.Duration = time.Since(start)
	return res, nil
}

func extractEntry(f *zip.File, root string, budget *security.Budget, opts *Options, res *Result) error {
	// Steps 1-2: canonicalise and assert containment before anything else.
	target, err := resolveTarget(root, f.Name, opts.AllowUnsafePaths)
	if err != nil {
		return err
	}

	info := f.FileInfo()
	entryMode := f.Mode()

	// Step 3: count the entry against the inode ceiling.
	if info.IsDir() {
		if err := budget.AddDirectory(f.Name); err != nil {
			return err
		}
		mode := security.DirMode(security.MaskMode(entryMode, opts.MaxMode))
		if err := os.MkdirAll(target, mode.Perm()); err != nil {
			return fmt.Errorf("cannot create directory %s: %w", f.Name, err)
		}
		res.createdDirs = append(res.createdDirs, filepath.Clean(filepath.FromSlash(f.Name)))
		return nil
	}
	if err := budget.AddFile(f.Name); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("cannot create parent directory for %s: %w", f.Name, err)
	}
	// Parents created implicitly here still need locking under -read-only.
	res.recordAncestors(f.Name)

	if entryMode&fs.ModeSymlink != 0 {
		return extractSymlink(f, root, target, res, opts)
	}
	if !entryMode.IsRegular() {
		// Devices, fifos, sockets: never legitimate in a portable archive.
		res.Warnings = append(res.Warnings,
			fmt.Sprintf("skipped non-regular entry %s (mode %v)", f.Name, entryMode))
		return nil
	}

	// Step 4: early-out on the declared size. Advisory only — the header is
	// attacker-controlled, so this can reject but never certify.
	if err := budget.CheckDeclaredSize(f.Name, int64(f.UncompressedSize64)); err != nil {
		return err
	}

	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("cannot read entry %s: %w", f.Name, err)
	}
	defer rc.Close()

	// Step 7: mask permissions. Step 8: write.
	mode := security.MaskMode(entryMode, opts.MaxMode)
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode.Perm())
	if err != nil {
		return fmt.Errorf("cannot create %s: %w", f.Name, err)
	}

	// Steps 5-6: stream, counting bytes as they are decompressed.
	written, copyErr := io.Copy(out, &countingReader{r: rc, budget: budget, entry: f.Name})
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return fmt.Errorf("cannot write %s: %w", f.Name, closeErr)
	}

	budget.AddCompressed(int64(f.CompressedSize64))
	if err := budget.CheckRatio(f.Name, written, int64(f.CompressedSize64)); err != nil {
		return err
	}

	// Step 9: the read-only lock, strictly after the data is written.
	if opts.ReadOnly {
		if err := chmodIfSupported(target, security.ReadOnlyMode(mode)); err != nil {
			return fmt.Errorf("cannot apply read-only permissions to %s: %w", f.Name, err)
		}
	}
	if opts.Log != nil && !opts.Quiet {
		opts.Log("  extracting: %s", f.Name)
	}
	return nil
}

// resolveTarget maps an entry name to a path on disk. With containment on it
// delegates to security.SafeJoin; with --secure=no it performs the naive join
// that standard unzip does, traversal and all.
func resolveTarget(root, name string, allowUnsafe bool) (string, error) {
	if !allowUnsafe {
		return security.SafeJoin(root, name)
	}
	if filepath.IsAbs(name) {
		return filepath.Clean(name), nil
	}
	return filepath.Clean(filepath.Join(root, filepath.FromSlash(name))), nil
}

func extractSymlink(f *zip.File, root, target string, res *Result, opts *Options) error {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("cannot read symlink entry %s: %w", f.Name, err)
	}
	defer rc.Close()

	// Symlink targets are tiny; a huge one is itself a red flag.
	raw, err := io.ReadAll(io.LimitReader(rc, 4096))
	if err != nil {
		return fmt.Errorf("cannot read symlink target for %s: %w", f.Name, err)
	}
	link := strings.TrimSpace(string(raw))

	if !opts.AllowUnsafePaths {
		if err := security.CheckSymlinkTarget(root, target, link); err != nil {
			return err
		}
	}
	if err := os.Symlink(link, target); err != nil {
		if runtime.GOOS == "windows" {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("skipped symlink %s (unprivileged Windows cannot create symlinks)", f.Name))
			return nil
		}
		return fmt.Errorf("cannot create symlink %s: %w", f.Name, err)
	}
	res.Symlinks++
	if opts.Log != nil && !opts.Quiet {
		opts.Log("  linking:    %s -> %s", f.Name, link)
	}
	return nil
}

// recordAncestors notes every directory implied by an entry name, so that
// -read-only can later lock exactly the directories this run created.
func (r *Result) recordAncestors(entryName string) {
	dir := filepath.Dir(filepath.Clean(filepath.FromSlash(entryName)))
	for dir != "." && dir != string(filepath.Separator) {
		r.createdDirs = append(r.createdDirs, dir)
		dir = filepath.Dir(dir)
	}
}

// lockDirectories strips write bits from the directories this run created,
// deepest first. Pre-existing directories in the destination are left alone —
// locking a directory the user already had would be an unrequested side effect.
func lockDirectories(dest string, rels []string) error {
	seen := make(map[string]bool, len(rels))
	unique := make([]string, 0, len(rels))
	for _, rel := range rels {
		if rel == "" || rel == "." || seen[rel] {
			continue
		}
		seen[rel] = true
		unique = append(unique, rel)
	}
	// Deepest first: a parent locked before its child would block the child's chmod.
	sort.Slice(unique, func(i, j int) bool { return len(unique[i]) > len(unique[j]) })

	for _, rel := range unique {
		p := filepath.Join(dest, rel)
		info, err := os.Stat(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		// Keep owner-execute: a directory that cannot be traversed cannot be read.
		if err := chmodIfSupported(p, security.ReadOnlyMode(info.Mode())|0o100); err != nil {
			return err
		}
	}
	return nil
}

// commit moves the staged tree into the destination. Directories are merged so
// that extracting into a populated directory behaves like unzip.
func commit(stage, dest string, overwrite bool) error {
	entries, err := os.ReadDir(stage)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := moveInto(filepath.Join(stage, e.Name()), filepath.Join(dest, e.Name()), overwrite); err != nil {
			return err
		}
	}
	return nil
}

func moveInto(src, dst string, overwrite bool) error {
	srcInfo, err := os.Lstat(src)
	if err != nil {
		return err
	}
	dstInfo, err := os.Lstat(dst)

	switch {
	case os.IsNotExist(err):
		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("cannot move %s into place: %w", filepath.Base(src), err)
		}
		return nil

	case err != nil:
		return err

	case srcInfo.IsDir() && dstInfo.IsDir():
		// Merge, recursing so existing sibling files are left alone.
		children, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, c := range children {
			if err := moveInto(filepath.Join(src, c.Name()), filepath.Join(dst, c.Name()), overwrite); err != nil {
				return err
			}
		}
		return nil

	case !overwrite:
		return fmt.Errorf("%s already exists (use -o to overwrite)", dst)

	default:
		if err := os.RemoveAll(dst); err != nil {
			return err
		}
		return os.Rename(src, dst)
	}
}
