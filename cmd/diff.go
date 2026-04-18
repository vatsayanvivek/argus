package cmd

// diff.go implements `argus diff --from <scan> --to <scan>` — compares two
// scan JSON files and prints added / resolved findings + chain changes.
// The same logic powers the dashboard's Drift view (/api/diff); this is the
// terminal-native path for people who don't want to run `argus serve`.

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/vatsayanvivek/argus/internal/models"
)

var (
	diffFrom     string
	diffTo       string
	diffJSON     bool
)

type diffScan struct {
	SubscriptionID string               `json:"subscription_id"`
	TenantID       string               `json:"tenant_id"`
	Findings       []models.Finding     `json:"findings"`
	Chains         []models.AttackChain `json:"chains"`
}

type diffOutput struct {
	From             string   `json:"from"`
	To               string   `json:"to"`
	AddedFindings    []string `json:"added_findings"`
	ResolvedFindings []string `json:"resolved_findings"`
	AddedChains      []string `json:"added_chains"`
	ResolvedChains   []string `json:"resolved_chains"`
}

var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Compare two scan JSON files (added / resolved findings and chains)",
	Long: `diff compares two scan JSON files produced by ` + "`argus scan --output json`" + `.
It prints which findings appeared, which were resolved, and which attack
chains changed state between scans.

  argus diff --from argus_20260401.json --to argus_20260418.json
  argus diff --from last-week.json --to today.json --json`,
	RunE: runDiff,
}

func init() {
	diffCmd.Flags().StringVar(&diffFrom, "from", "", "Older scan JSON file (required)")
	diffCmd.Flags().StringVar(&diffTo, "to", "", "Newer scan JSON file (required)")
	diffCmd.Flags().BoolVar(&diffJSON, "json", false, "Emit JSON instead of a human-readable table")
	_ = diffCmd.MarkFlagRequired("from")
	_ = diffCmd.MarkFlagRequired("to")
	rootCmd.AddCommand(diffCmd)
}

func runDiff(cmd *cobra.Command, args []string) error {
	from, err := loadScanJSON(diffFrom)
	if err != nil {
		return fmt.Errorf("load --from: %w", err)
	}
	to, err := loadScanJSON(diffTo)
	if err != nil {
		return fmt.Errorf("load --to: %w", err)
	}

	fromKeys := findingKeys(from.Findings)
	toKeys := findingKeys(to.Findings)
	added := diffKeys(toKeys, fromKeys, to.Findings)
	resolved := diffKeys(fromKeys, toKeys, from.Findings)

	fromChains := chainSet(from.Chains)
	toChains := chainSet(to.Chains)
	addedChains := setDiff(toChains, fromChains)
	resolvedChains := setDiff(fromChains, toChains)

	if diffJSON {
		out := diffOutput{
			From: diffFrom, To: diffTo,
			AddedFindings: renderFindingLabels(added),
			ResolvedFindings: renderFindingLabels(resolved),
			AddedChains: addedChains, ResolvedChains: resolvedChains,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	bold := color.New(color.Bold).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	fmt.Printf("Comparing:\n  from  %s\n  to    %s\n\n", cyan(diffFrom), cyan(diffTo))

	fmt.Printf("%s %d\n", bold(red("Added findings:")), len(added))
	for _, f := range added {
		fmt.Printf("  + %s  %-18s  %s  %s\n", sevColor(f.Severity, "●"), f.ID, f.ResourceName, truncateDiff(f.Title, 70))
	}
	fmt.Println()

	fmt.Printf("%s %d\n", bold(green("Resolved findings:")), len(resolved))
	for _, f := range resolved {
		fmt.Printf("  - %s  %-18s  %s  %s\n", sevColor(f.Severity, "●"), f.ID, f.ResourceName, truncateDiff(f.Title, 70))
	}
	fmt.Println()

	fmt.Printf("%s %s\n", bold("Added chains:"), fmtList(addedChains))
	fmt.Printf("%s %s\n", bold("Resolved chains:"), fmtList(resolvedChains))
	return nil
}

func sevColor(sev, text string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return color.New(color.FgRed, color.Bold).Sprint(text)
	case "HIGH":
		return color.New(color.FgHiYellow).Sprint(text)
	case "MEDIUM":
		return color.New(color.FgYellow).Sprint(text)
	case "LOW":
		return color.New(color.FgBlue).Sprint(text)
	}
	return text
}

func truncateDiff(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func loadScanJSON(path string) (*diffScan, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s diffScan
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func findingKeys(fs []models.Finding) map[string]models.Finding {
	out := make(map[string]models.Finding, len(fs))
	for _, f := range fs {
		k := f.ID + "|" + f.ResourceID
		out[k] = f
	}
	return out
}

func diffKeys(a, b map[string]models.Finding, source []models.Finding) []models.Finding {
	out := []models.Finding{}
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, a[k])
		}
	}
	// Stable sort for readability.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return severityOrdinal(out[i].Severity) < severityOrdinal(out[j].Severity)
		}
		return out[i].ID < out[j].ID
	})
	_ = source
	return out
}

func severityOrdinal(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	}
	return 4
}

func chainSet(cs []models.AttackChain) map[string]bool {
	out := map[string]bool{}
	for _, c := range cs {
		out[c.ID] = true
	}
	return out
}

func setDiff(a, b map[string]bool) []string {
	out := []string{}
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func renderFindingLabels(fs []models.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, fmt.Sprintf("%s %s %s", f.Severity, f.ID, f.ResourceID))
	}
	return out
}

func fmtList(xs []string) string {
	if len(xs) == 0 {
		return "(none)"
	}
	return strings.Join(xs, ", ")
}
