//go:build !windows

package main

import (
	"runtime"
	"syscall"
	"time"
)

// maxrssToBytes converts getrusage's ru_maxrss to bytes.
//
// The unit is NOT portable: Linux reports kilobytes, macOS and the BSDs report
// bytes. Sharing one code path would be wrong by a factor of 1024 on one of
// them, which is exactly the kind of bug that survives review because the
// number still looks plausible.
func maxrssToBytes(maxrss int64) uint64 {
	if maxrss < 0 {
		return 0
	}
	if runtime.GOOS == "linux" {
		return uint64(maxrss) * 1024
	}
	return uint64(maxrss)
}

func currentUsage() resourceUsage {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return resourceUsage{}
	}
	cpu := time.Duration(ru.Utime.Nano()) + time.Duration(ru.Stime.Nano())
	return resourceUsage{
		PeakRSSBytes: maxrssToBytes(int64(ru.Maxrss)),
		PeakRSSOK:    true,
		CPUTime:      cpu,
		CPUTimeOK:    true,
	}
}
