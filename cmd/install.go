package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// installCmd is the `argus install` subcommand — a self-installer
// built into the binary itself. Solves the "argus-windows-amd64.exe
// isn't on PATH" friction: users download the raw exe, run
//
//	.\argus-windows-amd64.exe install
//
// and it copies itself to a sensible location + adds that location
// to the user's PATH (Windows) or ~/.local/bin (macOS/Linux).
//
// No admin rights required on any platform. The install is idempotent:
// re-running overwrites the target binary so users can "re-install"
// to upgrade after downloading a newer exe.
var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install this binary to a standard location and put it on PATH",
	Long: `Copy the current argus executable to a standard location and put that
location on your PATH so you can run 'argus' from any terminal without
setting environment variables.

Platform install locations:
  Windows    %LOCALAPPDATA%\Programs\argus\argus.exe   (added to user PATH)
  macOS      ~/.local/bin/argus                        (added to PATH via shell profile)
  Linux      ~/.local/bin/argus                        (added to PATH via shell profile)

Idempotent — re-run to replace an existing install with a newer binary.
No admin/sudo required on any platform.`,
	RunE: runInstall,
}

var installForce bool

func init() {
	installCmd.Flags().BoolVar(&installForce, "force", false, "Overwrite existing install without prompting")
	rootCmd.AddCommand(installCmd)
}

func runInstall(cmd *cobra.Command, args []string) error {
	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate current executable: %w", err)
	}
	// Resolve any symlinks so we copy the real binary, not a pointer.
	if resolved, err := filepath.EvalSymlinks(selfPath); err == nil {
		selfPath = resolved
	}

	switch runtime.GOOS {
	case "windows":
		return installWindows(selfPath)
	case "darwin", "linux":
		return installUnix(selfPath)
	default:
		return fmt.Errorf("argus install is not supported on %s", runtime.GOOS)
	}
}

// installWindows copies the running exe to %LOCALAPPDATA%\Programs\argus\argus.exe
// and appends that directory to the user's PATH via the registry.
// Uses golang.org/x/sys/windows/registry (already a transitive
// dependency). Idempotent — existing PATH entries are not duplicated.
func installWindows(selfPath string) error {
	local := os.Getenv("LOCALAPPDATA")
	if local == "" {
		return fmt.Errorf("LOCALAPPDATA environment variable is empty")
	}
	installDir := filepath.Join(local, "Programs", "argus")
	targetPath := filepath.Join(installDir, "argus.exe")

	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return fmt.Errorf("create install dir: %w", err)
	}

	// If the running exe is already the target, skip the copy — that
	// means we were invoked as the installed binary (common if the
	// user re-runs install from PATH to refresh PATH registration).
	if strings.EqualFold(selfPath, targetPath) {
		fmt.Println("Running binary is already the installed binary; skipping copy.")
	} else {
		if err := copyFile(selfPath, targetPath); err != nil {
			return fmt.Errorf("copy binary: %w", err)
		}
		fmt.Printf("Installed binary to %s\n", targetPath)
	}

	if err := windowsAddUserPath(installDir); err != nil {
		return fmt.Errorf("update user PATH: %w", err)
	}

	fmt.Println()
	fmt.Println("PATH updated. Open a new PowerShell window and run:")
	fmt.Println("   argus --version")
	fmt.Println()
	fmt.Println("Existing PowerShell sessions must be restarted for PATH changes to apply.")
	return nil
}

// installUnix copies the binary to ~/.local/bin/argus (creating the
// directory if needed) and, if ~/.local/bin is not already on PATH,
// appends an export line to the appropriate shell profile
// (~/.zshrc, ~/.bashrc, or ~/.profile depending on which shell is
// configured for the user).
func installUnix(selfPath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("locate home dir: %w", err)
	}
	installDir := filepath.Join(home, ".local", "bin")
	targetPath := filepath.Join(installDir, "argus")

	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return fmt.Errorf("create install dir: %w", err)
	}

	if strings.EqualFold(selfPath, targetPath) {
		fmt.Println("Running binary is already the installed binary; skipping copy.")
	} else {
		if err := copyFile(selfPath, targetPath); err != nil {
			return fmt.Errorf("copy binary: %w", err)
		}
		// Ensure the copy is executable.
		_ = os.Chmod(targetPath, 0o755)
		fmt.Printf("Installed binary to %s\n", targetPath)
	}

	if !pathContains(installDir) {
		profile := unixShellProfile(home)
		line := fmt.Sprintf("\n# Added by `argus install`\nexport PATH=\"$HOME/.local/bin:$PATH\"\n")
		if err := appendUniqueLine(profile, line, "argus install"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not update %s: %v\n", profile, err)
			fmt.Fprintln(os.Stderr, "Add this line yourself:")
			fmt.Fprintln(os.Stderr, "   export PATH=\"$HOME/.local/bin:$PATH\"")
		} else {
			fmt.Printf("Added ~/.local/bin to PATH in %s\n", profile)
		}
	}

	fmt.Println()
	fmt.Println("Open a new terminal (or `source ~/.zshrc` / `source ~/.bashrc`) and run:")
	fmt.Println("   argus --version")
	return nil
}

// copyFile copies src to dst, atomically replacing dst if it exists.
// Uses a temp file + rename so an in-flight interruption never leaves
// a partial binary at the target path.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// On Windows, os.Rename fails if dst exists. Remove first.
	if runtime.GOOS == "windows" {
		_ = os.Remove(dst)
	}
	return os.Rename(tmp, dst)
}

// pathContains reports whether a directory appears in the current
// process's PATH environment. Case-insensitive on Windows, case-
// sensitive everywhere else.
func pathContains(dir string) bool {
	sep := ":"
	if runtime.GOOS == "windows" {
		sep = ";"
	}
	raw := os.Getenv("PATH")
	for _, entry := range strings.Split(raw, sep) {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if runtime.GOOS == "windows" {
			if strings.EqualFold(entry, dir) {
				return true
			}
		} else {
			if entry == dir {
				return true
			}
		}
	}
	return false
}

// unixShellProfile picks the profile file to append a PATH export to.
// Preference order:
//   1. ~/.zshrc if the user's login shell contains "zsh"
//   2. ~/.bashrc if it's bash
//   3. ~/.profile as a generic fallback
// Returns the path regardless of whether the file exists; appendUniqueLine
// creates the file if needed.
func unixShellProfile(home string) string {
	shell := os.Getenv("SHELL")
	switch {
	case strings.Contains(shell, "zsh"):
		return filepath.Join(home, ".zshrc")
	case strings.Contains(shell, "bash"):
		return filepath.Join(home, ".bashrc")
	}
	return filepath.Join(home, ".profile")
}

// appendUniqueLine appends `line` to `path` only if the given `marker`
// substring is not already present in the file, so re-running install
// does not duplicate the PATH export.
func appendUniqueLine(path, line, marker string) error {
	existing, err := os.ReadFile(path)
	if err == nil && strings.Contains(string(existing), marker) {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}
