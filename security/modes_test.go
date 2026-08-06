package security

import (
	"io/fs"
	"testing"
)

func TestMaskMode(t *testing.T) {
	cases := []struct {
		name  string
		entry fs.FileMode
		max   fs.FileMode
		want  fs.FileMode
	}{
		{"0777 masked to 0755", 0o777, 0o755, 0o755},
		{"0644 unchanged under 0755", 0o644, 0o755, 0o644},
		{"0777 masked to 0644", 0o777, 0o644, 0o644},
		{"executable survives 0755", 0o755, 0o755, 0o755},
		{"executable stripped by 0644", 0o755, 0o644, 0o644},
		{"unreadable entry gains owner-read", 0o000, 0o755, 0o400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MaskMode(tc.entry, tc.max); got.Perm() != tc.want.Perm() {
				t.Errorf("MaskMode(%o, %o) = %o, want %o", tc.entry, tc.max, got.Perm(), tc.want.Perm())
			}
		})
	}
}

// setuid/setgid/sticky are never legitimate in an extracted archive, so they
// are stripped even when masking is off (--secure=no).
func TestMaskModeAlwaysStripsDangerousBits(t *testing.T) {
	entry := 0o755 | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky

	for _, max := range []fs.FileMode{0o755, 0} {
		got := MaskMode(entry, max)
		if got&fs.ModeSetuid != 0 {
			t.Errorf("max=%o: setuid survived", max)
		}
		if got&fs.ModeSetgid != 0 {
			t.Errorf("max=%o: setgid survived", max)
		}
		if got&fs.ModeSticky != 0 {
			t.Errorf("max=%o: sticky survived", max)
		}
	}
}

func TestMaskModeZeroMeansNoMasking(t *testing.T) {
	if got := MaskMode(0o777, 0); got.Perm() != 0o777 {
		t.Errorf("MaskMode(0777, 0) = %o, want 0777 (masking off)", got.Perm())
	}
}

func TestReadOnlyMode(t *testing.T) {
	cases := map[fs.FileMode]fs.FileMode{
		0o644: 0o444,
		0o755: 0o555,
		0o600: 0o400,
		0o700: 0o500,
	}
	for in, want := range cases {
		if got := ReadOnlyMode(in); got.Perm() != want {
			t.Errorf("ReadOnlyMode(%o) = %o, want %o", in, got.Perm(), want)
		}
		if ReadOnlyMode(in).Perm()&0o222 != 0 {
			t.Errorf("ReadOnlyMode(%o) left a write bit set", in)
		}
	}
}

func TestDirModeIsTraversable(t *testing.T) {
	if got := DirMode(0o444); got&0o700 != 0o700 {
		t.Errorf("DirMode(0444) = %o, want owner rwx so the tree can be populated", got.Perm())
	}
}
