package cmd

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/vatsayanvivek/argus/internal/benchmark"
	"github.com/vatsayanvivek/argus/internal/engine"
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage and list ARGUS rules",
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all CIS + ARGUS ZT rules with metadata",
	RunE:  runRulesList,
}

func init() {
	rulesCmd.AddCommand(rulesListCmd)
}

func runRulesList(cmd *cobra.Command, args []string) error {
	bold := color.New(color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	red := color.New(color.FgRed, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	loader, err := benchmark.NewBenchmarkLoader()
	if err != nil {
		return fmt.Errorf("failed to load benchmark data: %w", err)
	}

	opa, err := engine.NewOPAEngine()
	if err != nil {
		return fmt.Errorf("failed to load OPA engine: %w", err)
	}

	cisCount := len(loader.CISRules)
	ztCount := 0
	for id := range opa.PolicyMetadata() {
		if len(id) >= 3 && id[:3] == "zt_" {
			ztCount++
		}
	}
	totalCount := cisCount + ztCount

	fmt.Println()
	fmt.Println(bold("══════════════════════════════════════════════════════════════════"))
	fmt.Println(bold("                       ARGUS Rule Library                          "))
	fmt.Println(bold("══════════════════════════════════════════════════════════════════"))
	fmt.Println()

	// Section 1: CIS rules
	fmt.Println(cyan(fmt.Sprintf("CIS Microsoft Azure Foundations Benchmark v2.0 (%d rules)", cisCount)))
	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "  RULE\tLEVEL\tNIST 800-53\tTITLE")
	fmt.Fprintln(w, "  ----\t-----\t-----------\t-----")

	cisIDs := make([]string, 0, len(loader.CISRules))
	for id := range loader.CISRules {
		cisIDs = append(cisIDs, id)
	}
	sort.Strings(cisIDs)
	for _, id := range cisIDs {
		r := loader.CISRules[id]
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", r.RuleID, r.Level, r.NIST80053, truncate(r.Title, 60))
	}
	w.Flush()
	fmt.Println()

	// Section 2: ARGUS ZT rules
	fmt.Println(cyan(fmt.Sprintf("ARGUS Zero Trust Custom Rules (%d rules)", ztCount)))
	fmt.Println()
	w2 := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w2, "  RULE\tPILLAR\tSEVERITY\tCHAIN ROLE\tTITLE")
	fmt.Fprintln(w2, "  ----\t------\t--------\t----------\t-----")

	ztIDs := []string{}
	metadata := opa.PolicyMetadata()
	for id := range metadata {
		if len(id) >= 3 && id[:3] == "zt_" {
			ztIDs = append(ztIDs, id)
		}
	}
	sort.Strings(ztIDs)
	for _, id := range ztIDs {
		m := metadata[id]
		sev := m.Severity
		switch sev {
		case "CRITICAL":
			sev = red(sev)
		case "HIGH":
			sev = yellow(sev)
		}
		fmt.Fprintf(w2, "  %s\t%s\t%s\t%s\t%s\n", m.ID, m.Pillar, sev, m.ChainRole, truncate(m.Title, 50))
	}
	w2.Flush()
	fmt.Println()

	fmt.Println(bold("══════════════════════════════════════════════════════════════════"))
	fmt.Printf("  Total checks evaluated: %s\n", cyan(fmt.Sprintf("%d", totalCount)))
	fmt.Println(bold("══════════════════════════════════════════════════════════════════"))
	fmt.Println()
	return nil
}
