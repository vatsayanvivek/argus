package cmd

// scan_resume.go wires scan-time checkpointing into the CLI. A scan id
// names a checkpoint directory on disk that stores per-sub-collector
// results. `argus scan --resume <id>` replays those results instead of
// re-calling Azure; `argus scan --list-resumable` enumerates partially
// completed scans so the user doesn't have to remember the id.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"

	"github.com/vatsayanvivek/argus/internal/collector/azure"
)

// checkpointBaseDir returns ~/.argus/scan-state. The directory is
// created lazily by the Checkpointer, not here.
func checkpointBaseDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, ".argus", "scan-state"), nil
}

// resolveScanID returns the scan id to use for the current run. If
// --resume was passed, the id is validated (directory must exist) and
// echoed back. Otherwise a fresh id is minted in the form
// scan-YYYYMMDDTHHMMSSZ-<6 hex chars>-<short-sub-id> which is sortable,
// unique, and carries the subscription prefix for human recognition.
func resolveScanID(resumeID, subscriptionID string) (string, error) {
	if resumeID != "" {
		base, err := checkpointBaseDir()
		if err != nil {
			return "", err
		}
		dir := filepath.Join(base, resumeID)
		if _, err := os.Stat(dir); err != nil {
			return "", fmt.Errorf("--resume: scan id %q has no checkpoint at %s", resumeID, dir)
		}
		return resumeID, nil
	}
	// Fresh id: timestamp + 6 hex + 4-char sub prefix.
	buf := make([]byte, 3)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	shortSub := subscriptionID
	if len(shortSub) > 4 {
		shortSub = shortSub[:4]
	}
	return fmt.Sprintf("scan-%s-%s-%s",
		time.Now().UTC().Format("20060102T150405Z"),
		hex.EncodeToString(buf),
		shortSub,
	), nil
}

// runListResumable implements `argus scan --list-resumable`. It walks
// ~/.argus/scan-state/ and prints one line per resumable scan with
// subscription, tenant, age, and a compact status of which services
// still need to run.
func runListResumable() error {
	base, err := checkpointBaseDir()
	if err != nil {
		return err
	}
	scans, err := azure.ListResumable(base)
	if err != nil {
		return fmt.Errorf("list checkpoints: %w", err)
	}
	if len(scans) == 0 {
		fmt.Println("No resumable scans. (Checkpoints are cleaned up after a successful full collection.)")
		return nil
	}

	bold := color.New(color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	fmt.Printf("%-55s  %-38s  %-38s  %s\n",
		bold("SCAN ID"), bold("SUBSCRIPTION"), bold("TENANT"), bold("PENDING"))
	for _, s := range scans {
		age := time.Since(s.UpdatedAt).Truncate(time.Second)
		fmt.Printf("%-55s  %-38s  %-38s  %s %s\n",
			cyan(s.ScanID),
			s.SubscriptionID,
			s.TenantID,
			yellow(fmt.Sprintf("%v", s.Missing)),
			fmt.Sprintf("(%s ago)", age),
		)
	}
	fmt.Println()
	fmt.Println("Resume with:  argus scan --tenant <tenant> --subscription <sub> --resume <scan-id>")
	return nil
}
