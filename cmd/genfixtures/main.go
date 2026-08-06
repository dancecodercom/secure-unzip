// Command genfixtures writes the test archives to a directory. It exists so
// the benchmark script (bash) can produce the same fixtures the Go tests use,
// without duplicating the generators in another language.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pforret/secure-unzip/testutils"
)

func main() {
	dir := flag.String("d", "testdata/tmp", "directory to write fixtures into")
	largeMB := flag.Int64("large-mb", 0, "also write large-benign.zip of roughly this many MB")
	flag.Parse()

	paths, err := testutils.Generate(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "genfixtures:", err)
		os.Exit(1)
	}
	for name, p := range paths {
		fmt.Printf("%-10s %s\n", name, p)
	}

	if *largeMB > 0 {
		p := filepath.Join(*dir, "large-benign.zip")
		if err := testutils.LargeBenign(p, *largeMB*1000*1000); err != nil {
			fmt.Fprintln(os.Stderr, "genfixtures:", err)
			os.Exit(1)
		}
		fmt.Printf("%-10s %s\n", "large", p)
	}
}
