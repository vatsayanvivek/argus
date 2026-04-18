package cmd

// explain.go adds `argus explain <rule-or-chain-id>` — a terminal-native way
// to read a rule's description + compliance mapping or a chain's narrative,
// steps, and blast radius without opening a browser. Security teams who live
// in a shell expect this, and it keeps ARGUS usable offline where the docs
// site isn't reachable.

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/vatsayanvivek/argus/internal/engine"
	"github.com/vatsayanvivek/argus/internal/models"
)

var explainCmd = &cobra.Command{
	Use:   "explain <rule-id | chain-id>",
	Short: "Show the narrative, mapping, and attack steps for a rule or chain",
	Long: `Explain prints a human-readable description of an ARGUS rule or attack chain.
Rule IDs look like zt_id_001, zt_net_012, cis_6_1. Chain IDs look like CHAIN-001.
Run without an argument to see a searchable index of both rules and chains.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runExplain,
}

func init() {
	rootCmd.AddCommand(explainCmd)
}

func runExplain(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return runExplainIndex()
	}
	id := args[0]
	switch {
	case strings.HasPrefix(strings.ToUpper(id), "CHAIN-"):
		return runExplainChain(strings.ToUpper(id))
	default:
		return runExplainRule(id)
	}
}

func runExplainRule(id string) error {
	eng, err := engine.NewOPAEngine()
	if err != nil {
		return fmt.Errorf("load engine: %w", err)
	}
	meta, ok := eng.PolicyMetadata()[id]
	if !ok {
		return fmt.Errorf("unknown rule id %q (try: argus explain — no args — for the full catalog)", id)
	}

	bold := color.New(color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	dim := color.New(color.Faint).SprintFunc()

	fmt.Printf("%s  %s\n", bold(meta.ID), cyan(meta.Title))
	fmt.Println(strings.Repeat("─", 72))
	fmt.Printf("%s     %s  %s     %s  %s     %s\n",
		dim("Severity:"), bold(meta.Severity),
		dim("Pillar:"), bold(meta.Pillar),
		dim("Role:"), bold(meta.ChainRole))
	fmt.Println()
	fmt.Println(wrap(meta.Description, 72))
	fmt.Println()

	fmt.Println(bold("Mapping"))
	printKV("  NIST 800-53       ", meta.NIST80053)
	printKV("  NIST 800-207      ", meta.NIST800207)
	printKV("  CIS Azure         ", meta.CISRule)
	printKV("  MITRE Technique   ", meta.MITRETechnique)
	printKV("  MITRE Tactic      ", meta.MITRETactic)
	printKV("  Zero-Trust Tenet  ", meta.ZTTenet)
	if len(meta.Frameworks) > 0 {
		printKV("  Framework tags    ", strings.Join(meta.Frameworks, ", "))
	}
	fmt.Println()
	return nil
}

func runExplainChain(id string) error {
	c := engine.NewCorrelator()
	var found *models.AttackChain
	for _, ex := range c.ExampleChains() {
		if ex.ID == id {
			copy := ex
			found = &copy
			break
		}
	}
	if found == nil {
		return fmt.Errorf("unknown chain id %q (try: argus explain — no args — for the full catalog)", id)
	}

	bold := color.New(color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed, color.Bold).SprintFunc()
	dim := color.New(color.Faint).SprintFunc()

	severityColor := cyan
	switch strings.ToUpper(found.Severity) {
	case "CRITICAL":
		severityColor = red
	case "HIGH":
		severityColor = yellow
	}

	fmt.Printf("%s  %s\n", bold(found.ID), cyan(found.Title))
	fmt.Println(strings.Repeat("─", 72))
	fmt.Printf("%s %s   %s %s   %s %s\n",
		dim("Severity:"), severityColor(found.Severity),
		dim("Likelihood:"), bold(found.Likelihood),
		dim("Logic:"), bold(found.TriggerLogic))
	fmt.Println()

	fmt.Println(bold("Why this chain matters"))
	fmt.Println(wrap(found.Narrative, 72))
	fmt.Println()

	if len(found.TriggerFindings) > 0 {
		fmt.Println(bold("Trigger rules"))
		for _, r := range found.TriggerFindings {
			fmt.Printf("  • %s\n", cyan(r))
		}
		fmt.Println()
	}

	if len(found.Steps) > 0 {
		fmt.Println(bold("Attack walkthrough"))
		for _, s := range found.Steps {
			fmt.Printf("  %s %s\n", dim(fmt.Sprintf("Step %d.", s.Number)), bold(s.Action))
			if s.Actor != "" {
				fmt.Printf("    %s %s\n", dim("actor:"), s.Actor)
			}
			if s.Technique != "" {
				fmt.Printf("    %s %s\n", dim("MITRE:"), s.Technique)
			}
			if s.EnabledBy != "" {
				fmt.Printf("    %s %s\n", dim("enabled by:"), cyan(s.EnabledBy))
			}
			if s.Technical != "" {
				fmt.Printf("    %s\n", dim(wrap(s.Technical, 68)))
			}
			if s.Gain != "" {
				fmt.Printf("    %s %s\n", dim("gain:"), s.Gain)
			}
			fmt.Println()
		}
	}

	br := found.BlastRadius
	if br.InitialAccess != "" || br.MaxPrivilege != "" {
		fmt.Println(bold("Blast radius"))
		printKV("  Initial access    ", br.InitialAccess)
		printKV("  Lateral movement  ", br.LateralMovement)
		printKV("  Max privilege     ", br.MaxPrivilege)
		if len(br.DataAtRisk) > 0 {
			printKV("  Data at risk      ", strings.Join(br.DataAtRisk, ", "))
		}
		if len(br.ServicesAtRisk) > 0 {
			printKV("  Services at risk  ", strings.Join(br.ServicesAtRisk, ", "))
		}
		fmt.Println()
	}
	return nil
}

func runExplainIndex() error {
	eng, err := engine.NewOPAEngine()
	if err != nil {
		return fmt.Errorf("load engine: %w", err)
	}
	bold := color.New(color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	dim := color.New(color.Faint).SprintFunc()

	fmt.Println(bold("Chains"))
	for _, ex := range engine.NewCorrelator().ExampleChains() {
		fmt.Printf("  %-12s  %s\n", cyan(ex.ID), ex.Title)
	}
	fmt.Println()

	fmt.Println(bold("Rules"))
	// Group by pillar for scanability.
	byPillar := map[string][]engine.PolicyMetadata{}
	for _, m := range eng.PolicyMetadata() {
		byPillar[m.Pillar] = append(byPillar[m.Pillar], m)
	}
	pillars := []string{}
	for p := range byPillar {
		pillars = append(pillars, p)
	}
	sortStrings(pillars)
	for _, p := range pillars {
		fmt.Printf("  %s\n", dim(p))
		list := byPillar[p]
		sortMeta(list)
		for _, m := range list {
			fmt.Printf("    %-16s  %s\n", cyan(m.ID), truncateExplain(m.Title, 60))
		}
	}
	fmt.Println()
	fmt.Printf("Run %s for detail.\n", bold("argus explain <id>"))
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func printKV(label, val string) {
	if strings.TrimSpace(val) == "" {
		return
	}
	dim := color.New(color.Faint).SprintFunc()
	fmt.Printf("%s  %s\n", dim(label), val)
}

func wrap(s string, width int) string {
	if s == "" {
		return ""
	}
	words := strings.Fields(s)
	var b strings.Builder
	line := 0
	for i, w := range words {
		if line+len(w)+1 > width && line > 0 {
			b.WriteString("\n")
			line = 0
		}
		if line > 0 {
			b.WriteString(" ")
			line++
		}
		b.WriteString(w)
		line += len(w)
		if i == len(words)-1 {
			break
		}
	}
	return b.String()
}

func truncateExplain(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func sortMeta(m []engine.PolicyMetadata) {
	for i := 1; i < len(m); i++ {
		for j := i; j > 0 && m[j-1].ID > m[j].ID; j-- {
			m[j-1], m[j] = m[j], m[j-1]
		}
	}
}

// interface check — keep to squelch unused-import warnings if refactored.
var _ = os.Stdout
