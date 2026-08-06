package security

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeJoinRejectsEscapes(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "tmp", "dest")

	malicious := []struct {
		name  string
		entry string
	}{
		{"classic zip slip", "../../etc/passwd"},
		{"single parent", "../evil"},
		{"absolute posix", "/etc/passwd"},
		{"nested traversal", "a/b/../../../evil"},
		{"traversal after clean prefix", "safe/../../evil"},
		{"windows separators", `..\..\evil`},
		{"windows drive", `C:\Windows\System32\evil`},
		{"windows drive relative", "C:evil"},
		{"unc path", "//host/share/evil"},
		{"trailing parent", "a/.."},
		{"only parent", ".."},
		{"only dot", "."},
		{"empty", ""},
		{"nul byte", "a\x00b"},
	}

	for _, tc := range malicious {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SafeJoin(root, tc.entry)
			if err == nil {
				t.Fatalf("SafeJoin(%q) = %q, want a constraint error", tc.entry, got)
			}
			ce, ok := AsConstraintError(err)
			if !ok {
				t.Fatalf("SafeJoin(%q) returned %T, want *ConstraintError", tc.entry, err)
			}
			if ce.Constraint != ConstraintZipSlip {
				t.Errorf("constraint = %q, want %q", ce.Constraint, ConstraintZipSlip)
			}
			// The error message must name the constraint (CLAUDE.md §5).
			if !strings.Contains(ce.Error(), ConstraintZipSlip) {
				t.Errorf("error %q does not name its constraint", ce.Error())
			}
		})
	}
}

func TestSafeJoinAcceptsLegitimateNames(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "tmp", "dest")

	ok := []struct {
		entry string
		want  string
	}{
		{"file.txt", filepath.Join(root, "file.txt")},
		{"dir/file.txt", filepath.Join(root, "dir", "file.txt")},
		{"a/b/c/d/e/deep.txt", filepath.Join(root, "a", "b", "c", "d", "e", "deep.txt")},
		{"./relative.txt", filepath.Join(root, "relative.txt")},
		{"a//double//slash.txt", filepath.Join(root, "a", "double", "slash.txt")},
		{"ünïcødé-名前.txt", filepath.Join(root, "ünïcødé-名前.txt")},
		{"file with spaces.txt", filepath.Join(root, "file with spaces.txt")},
		{"..hidden/..leading-dots.txt", filepath.Join(root, "..hidden", "..leading-dots.txt")},
		{"dir/", filepath.Join(root, "dir")},
	}

	for _, tc := range ok {
		t.Run(tc.entry, func(t *testing.T) {
			got, err := SafeJoin(root, tc.entry)
			if err != nil {
				t.Fatalf("SafeJoin(%q) unexpected error: %v", tc.entry, err)
			}
			if got != tc.want {
				t.Errorf("SafeJoin(%q) = %q, want %q", tc.entry, got, tc.want)
			}
		})
	}
}

func TestContains(t *testing.T) {
	sep := string(filepath.Separator)
	root := sep + filepath.Join("tmp", "dest")

	cases := []struct {
		target string
		want   bool
	}{
		{filepath.Join(root, "file"), true},
		{filepath.Join(root, "a", "b"), true},
		{root, false},                                      // root itself is not "inside"
		{sep + filepath.Join("tmp", "destination"), false}, // prefix-but-not-parent
		{sep + filepath.Join("tmp"), false},
		{sep + filepath.Join("etc", "passwd"), false},
	}

	for _, tc := range cases {
		if got := Contains(root, tc.target); got != tc.want {
			t.Errorf("Contains(%q, %q) = %v, want %v", root, tc.target, got, tc.want)
		}
	}
}

// TestContainsSiblingPrefix guards the specific bug where a naive
// strings.HasPrefix without a separator lets /tmp/destination pass as being
// inside /tmp/dest.
func TestContainsSiblingPrefix(t *testing.T) {
	sep := string(filepath.Separator)
	root := sep + "dest"
	if Contains(root, sep+"destroy-everything") {
		t.Fatal("sibling directory with a shared prefix must not count as contained")
	}
}

func TestCheckSymlinkTarget(t *testing.T) {
	sep := string(filepath.Separator)
	root := sep + filepath.Join("tmp", "dest")
	link := filepath.Join(root, "sub", "link")

	escapes := []struct {
		name   string
		target string
	}{
		{"absolute", "/etc/passwd"},
		{"traversal out", "../../etc/passwd"},
		{"traversal to root itself", ".."},
		{"windows absolute", `C:\Windows`},
		{"unc", "//host/share"},
		{"empty", ""},
		{"deep traversal", "../../../../../../etc/shadow"},
	}
	for _, tc := range escapes {
		t.Run("escape/"+tc.name, func(t *testing.T) {
			err := CheckSymlinkTarget(root, link, tc.target)
			if err == nil {
				t.Fatalf("CheckSymlinkTarget(%q) = nil, want a constraint error", tc.target)
			}
			ce, ok := AsConstraintError(err)
			if !ok || ce.Constraint != ConstraintSymlinkEscape {
				t.Fatalf("got %v, want a %s constraint error", err, ConstraintSymlinkEscape)
			}
		})
	}

	contained := []string{
		"sibling",
		"./sibling",
		"../other/file",      // up to root/other — still inside
		"deeper/nested/file", //
	}
	for _, target := range contained {
		t.Run("allowed/"+target, func(t *testing.T) {
			if err := CheckSymlinkTarget(root, link, target); err != nil {
				t.Errorf("CheckSymlinkTarget(%q) unexpected error: %v", target, err)
			}
		})
	}
}
