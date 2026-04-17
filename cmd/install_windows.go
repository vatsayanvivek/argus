//go:build windows

package cmd

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

// windowsAddUserPath appends `dir` to the current user's PATH via the
// HKCU\Environment registry key, then broadcasts WM_SETTINGCHANGE so
// newly launched processes (like future PowerShell windows) pick up
// the change without requiring a logout. The entry is not duplicated
// if it already exists.
//
// User-scope PATH (HKCU) does not require admin rights, which is the
// whole point of installing into %LOCALAPPDATA%: the install never
// asks the user for an elevation prompt.
func windowsAddUserPath(dir string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open HKCU\\Environment: %w", err)
	}
	defer key.Close()

	// Read existing PATH. GetStringValue returns ErrNotExist if the
	// user has never had a custom PATH; treat that as empty.
	current, _, err := key.GetStringValue("Path")
	if err != nil && err != registry.ErrNotExist {
		return fmt.Errorf("read existing PATH: %w", err)
	}

	// If dir is already on PATH (case-insensitive), nothing to do.
	for _, entry := range strings.Split(current, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.EqualFold(entry, dir) {
			fmt.Printf("%s is already on user PATH; no change needed.\n", dir)
			return nil
		}
	}

	// Append. Guard against a trailing semicolon so we don't end up
	// with empty path entries (harmless but cosmetically bad).
	updated := strings.TrimRight(current, ";")
	if updated != "" {
		updated += ";"
	}
	updated += dir

	// Use REG_EXPAND_SZ so the value can still contain %-variables if
	// the user had them. SetStringValue defaults to REG_SZ; we need
	// SetExpandStringValue for parity with Windows's own behaviour.
	if err := key.SetExpandStringValue("Path", updated); err != nil {
		return fmt.Errorf("write PATH: %w", err)
	}

	// Broadcast WM_SETTINGCHANGE so already-running shells reload env.
	// This is best-effort — failure is non-fatal because a new terminal
	// will see the change regardless.
	broadcastEnvChanged()

	fmt.Printf("Added %s to user PATH.\n", dir)
	return nil
}

// broadcastEnvChanged sends the WM_SETTINGCHANGE message to all top-
// level windows so Explorer (and any process listening for env
// updates) refreshes its environment cache. Without this, new
// PowerShell windows launched from Explorer would still see the old
// PATH until the user logged out and back in.
//
// We call SendMessageTimeoutW with a short timeout and ignore errors;
// a failed broadcast only delays when the change is visible, it never
// corrupts anything.
func broadcastEnvChanged() {
	user32, err := syscall.LoadDLL("user32.dll")
	if err != nil {
		return
	}
	proc, err := user32.FindProc("SendMessageTimeoutW")
	if err != nil {
		return
	}
	const HWND_BROADCAST = 0xFFFF
	const WM_SETTINGCHANGE = 0x001A
	const SMTO_ABORTIFHUNG = 0x0002

	msg, _ := syscall.UTF16PtrFromString("Environment")
	var result uintptr
	_, _, _ = proc.Call(
		uintptr(HWND_BROADCAST),
		uintptr(WM_SETTINGCHANGE),
		0,
		uintptr(unsafe.Pointer(msg)),
		uintptr(SMTO_ABORTIFHUNG),
		uintptr(1000), // 1-second timeout
		uintptr(unsafe.Pointer(&result)),
	)
}
