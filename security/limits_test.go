package security

import "testing"

func TestBudgetMaxFiles(t *testing.T) {
	b := NewBudget(Limits{MaxFiles: 3})
	for i := 0; i < 3; i++ {
		if err := b.AddFile("f"); err != nil {
			t.Fatalf("file %d unexpectedly rejected: %v", i, err)
		}
	}
	err := b.AddFile("one-too-many")
	ce, ok := AsConstraintError(err)
	if !ok || ce.Constraint != ConstraintMaxFiles {
		t.Fatalf("got %v, want a %s constraint error", err, ConstraintMaxFiles)
	}
}

// Directories consume inodes, so they must count against the same ceiling.
func TestBudgetDirectoriesCountAsFiles(t *testing.T) {
	b := NewBudget(Limits{MaxFiles: 2})
	if err := b.AddDirectory("d1"); err != nil {
		t.Fatal(err)
	}
	if err := b.AddFile("f1"); err != nil {
		t.Fatal(err)
	}
	if err := b.AddDirectory("d2"); err == nil {
		t.Fatal("third entry should breach MaxFiles=2")
	}
}

func TestBudgetMaxSize(t *testing.T) {
	b := NewBudget(Limits{MaxSize: 1000})
	if err := b.AddBytes("e", 999); err != nil {
		t.Fatalf("under the limit: %v", err)
	}
	if err := b.AddBytes("e", 1); err != nil {
		t.Fatalf("exactly at the limit must be allowed: %v", err)
	}
	err := b.AddBytes("e", 1)
	ce, ok := AsConstraintError(err)
	if !ok || ce.Constraint != ConstraintMaxSize {
		t.Fatalf("got %v, want a %s constraint error", err, ConstraintMaxSize)
	}
}

// Zero means unlimited — this is how --secure=no is expressed.
func TestBudgetZeroMeansUnlimited(t *testing.T) {
	b := NewBudget(UnsecureLimits())
	if err := b.AddBytes("e", 1<<40); err != nil {
		t.Errorf("MaxSize=0 must not limit: %v", err)
	}
	for i := 0; i < 100000; i++ {
		if err := b.AddFile("f"); err != nil {
			t.Fatalf("MaxFiles=0 must not limit: %v", err)
		}
	}
	if err := b.CheckRatio("e", 1<<30, 1); err != nil {
		t.Errorf("MaxRatio=0 must not limit: %v", err)
	}
}

func TestBudgetRatio(t *testing.T) {
	b := NewBudget(Limits{MaxRatio: 100})

	// Below the size floor: a huge ratio on a tiny entry is meaningless.
	if err := b.CheckRatio("small", 1000, 1); err != nil {
		t.Errorf("entries under the floor must be exempt: %v", err)
	}
	// Above the floor, within the ratio.
	if err := b.CheckRatio("ok", 10<<20, 1<<20); err != nil {
		t.Errorf("10:1 is under the 100:1 ceiling: %v", err)
	}
	// Above the floor, bomb-like ratio.
	err := b.CheckRatio("bomb", 1<<30, 1024)
	ce, ok := AsConstraintError(err)
	if !ok || ce.Constraint != ConstraintMaxRatio {
		t.Fatalf("got %v, want a %s constraint error", err, ConstraintMaxRatio)
	}
}

// The declared size is attacker-controlled: it may only ever reject early,
// never certify. A lying header must still be caught by AddBytes.
func TestDeclaredSizeIsOnlyAnEarlyOut(t *testing.T) {
	b := NewBudget(Limits{MaxSize: 1000})
	if err := b.CheckDeclaredSize("liar", 10); err != nil {
		t.Fatalf("a small declared size must pass the early-out: %v", err)
	}
	if err := b.AddBytes("liar", 5000); err == nil {
		t.Fatal("streaming accounting must catch a header that understated the size")
	}

	b2 := NewBudget(Limits{MaxSize: 1000})
	if err := b2.CheckDeclaredSize("honest", 5000); err == nil {
		t.Fatal("an oversized declared size should be rejected early")
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		512:         "512 B",
		1024:        "1.0 KiB",
		10737418240: "10.0 GiB",
	}
	for in, want := range cases {
		if got := HumanBytes(in); got != want {
			t.Errorf("HumanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}
