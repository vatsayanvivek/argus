package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
)

// cleanupPostUpdate removes a previous version's binary that
// `argus update` renamed to ".old" as part of the atomic-swap dance
// on Windows. Runs on every startup; a no-op when the file doesn't
// exist.
func cleanupPostUpdate() {
	if runtime.GOOS != "windows" {
		return
	}
	self, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	_ = os.Remove(self + ".old")
}

var version = "1.1.1"

// SetVersion is called from main to inject the build-time version.
func SetVersion(v string) {
	version = v
}

var rootCmd = &cobra.Command{
	Use:   "argus",
	Short: "ARGUS — Offensive Risk & Chain Analysis Platform for Microsoft Azure",
	Long: `ARGUS finds attack chains in Microsoft Azure environments.

Individual misconfigurations may pass every scanner in isolation.
ARGUS finds what happens when they combine — the exact path an
attacker would take through them.

Built on Azure Resource Graph, OPA/Rego policies, and a chain
correlation engine that models how findings interact.

First-time setup:
  If you downloaded the binary directly and "argus" isn't on your PATH,
  run "argus install" once and it'll put the binary in a standard
  location + update PATH. No admin required.`,
}

// Execute runs the root command.
func Execute() {
	// Clean up the ".old" sidecar left behind by a Windows self-
	// update. On Linux/macOS this is a no-op.
	cleanupPostUpdate()

	if err := rootCmd.Execute(); err != nil {
		var ciErr *CIGateError
		if errors.As(err, &ciErr) {
			fmt.Fprintln(os.Stderr, ciErr.Message)
			os.Exit(ciErr.ExitCode)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Version = version
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(scoreCmd)
	rootCmd.AddCommand(driftCmd)
	rootCmd.AddCommand(suppressCmd)
	rootCmd.AddCommand(trendCmd)
	rootCmd.AddCommand(monitorCmd)
}
