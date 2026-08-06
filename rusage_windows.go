//go:build windows

package main

// Windows has no getrusage. Rather than pull in the syscalls for
// GetProcessMemoryInfo, report the resource lines as unavailable — --verbose
// still prints parameters, counts and throughput, which is most of its value.
// Filling this in is tracked as follow-up work.
func currentUsage() resourceUsage {
	return resourceUsage{}
}
