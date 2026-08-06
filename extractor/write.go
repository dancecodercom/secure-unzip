package extractor

import (
	"io"

	"github.com/pforret/secure-unzip/security"
)

// countingReader charges every byte read against the budget as it is read.
//
// This is the control that actually stops a zip bomb. Checking sizes after the
// fact would mean the bomb has already expanded onto the disk; checking the
// header alone would trust an attacker-controlled number. Counting here means
// extraction halts mid-entry, at the moment the ceiling is crossed.
type countingReader struct {
	r      io.Reader
	budget *security.Budget
	entry  string
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		if bErr := c.budget.AddBytes(c.entry, int64(n)); bErr != nil {
			return n, bErr
		}
	}
	return n, err
}
