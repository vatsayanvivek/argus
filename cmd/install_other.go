//go:build !windows

package cmd

import "fmt"

// windowsAddUserPath is a no-op stub on non-Windows builds. The
// Windows build replaces this via the //go:build windows file.
// runInstall never calls it off Windows because installWindows is
// reached only via runtime.GOOS == "windows".
func windowsAddUserPath(dir string) error {
	return fmt.Errorf("windowsAddUserPath called on non-Windows build — this should be unreachable")
}
