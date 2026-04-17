package cmd

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/vatsayanvivek/argus/internal/benchmark"
	"github.com/vatsayanvivek/argus/internal/engine"
	"github.com/vatsayanvivek/argus/internal/suppression"
)

var (
	suppressRule       string
	suppressResource   string
	suppressReason     string
	suppressApprovedBy string
	suppressExpires    string
	suppressFile       string
	suppressYes        bool
)

var suppressCmd = &cobra.Command{
	Use:   "suppress",
	Short: "Append a finding suppression to .argusignore",
	Long: `Append a new suppression entry to the .argusignore file.

Suppressions move findings into the "Suppressed Findings" section of
the report instead of silently dropping them — the reason, approver,
and expiry are always recorded so accepted-risk decisions remain
auditable.`,
	RunE: runSuppress,
}

func init() {
	suppressCmd.Flags().StringVar(&suppressRule, "rule", "", "Rule ID to suppress (e.g. zt_net_001) — required")
	suppressCmd.Flags().StringVar(&suppressResource, "resource", "*", "Resource ID to scope to (default '*' = all resources)")
	suppressCmd.Flags().StringVar(&suppressReason, "reason", "", "Reason for the suppression — required")
	suppressCmd.Flags().StringVar(&suppressApprovedBy, "approved-by", "", "Person or team approving the suppression — required")
	suppressCmd.Flags().StringVar(&suppressExpires, "expires", "", "Expiry date YYYY-MM-DD (optional, blank = never)")
	suppressCmd.Flags().StringVar(&suppressFile, "file", ".argusignore", "Suppression file to update")
	suppressCmd.Flags().BoolVar(&suppressYes, "yes", false, "Skip the confirmation prompt")
	_ = suppressCmd.MarkFlagRequired("rule")
	_ = suppressCmd.MarkFlagRequired("reason")
	_ = suppressCmd.MarkFlagRequired("approved-by")
}

func runSuppress(cmd *cobra.Command, args []string) error {
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed, color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()

	// Validate the rule exists in the loaded rule library.
	known, err := allKnownRuleIDs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not load rule library to validate ID: %v\n", err)
	} else if _, ok := known[suppressRule]; !ok {
		fmt.Println(red("Error:") + fmt.Sprintf(" rule %q is not a known ARGUS rule.", suppressRule))
		fmt.Println("Run " + cyan("argus rules list") + " to see all valid rule IDs.")
		// Suggest closest match.
		if best := closestRuleID(known, suppressRule); best != "" {
			fmt.Printf("Did you mean %s?\n", cyan(best))
		}
		return fmt.Errorf("unknown rule id %q", suppressRule)
	}

	// Validate expires date if provided.
	if suppressExpires != "" {
		t, err := time.Parse("2006-01-02", suppressExpires)
		if err != nil {
			return fmt.Errorf("invalid --expires date %q: must be YYYY-MM-DD", suppressExpires)
		}
		if t.Before(time.Now()) {
			return fmt.Errorf("--expires %s is already in the past", suppressExpires)
		}
	}

	entry := suppression.Suppression{
		RuleID:     suppressRule,
		ResourceID: suppressResource,
		Reason:     suppressReason,
		ApprovedBy: suppressApprovedBy,
		Expires:    suppressExpires,
		CreatedAt:  time.Now().UTC().Format("2006-01-02"),
	}

	// Show preview and confirm.
	fmt.Println()
	fmt.Println(cyan("New suppression entry:"))
	fmt.Printf("  rule_id:     %s\n", entry.RuleID)
	fmt.Printf("  resource_id: %s\n", entry.ResourceID)
	fmt.Printf("  reason:      %s\n", entry.Reason)
	fmt.Printf("  approved_by: %s\n", entry.ApprovedBy)
	if entry.Expires != "" {
		fmt.Printf("  expires:     %s\n", entry.Expires)
	} else {
		fmt.Printf("  expires:     %s\n", yellow("never"))
	}
	fmt.Printf("  file:        %s\n", suppressFile)
	fmt.Println()

	if !suppressYes {
		fmt.Print(yellow("Append this entry to .argusignore? [y/N] "))
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "y" && answer != "yes" {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	if err := suppression.Append(suppressFile, entry); err != nil {
		return fmt.Errorf("append suppression: %w", err)
	}
	fmt.Println(green("[OK]") + " suppression appended to " + suppressFile)
	return nil
}

// allKnownRuleIDs returns the set of every CIS and ZT rule ID currently
// loaded in the engine + benchmark library.
func allKnownRuleIDs() (map[string]bool, error) {
	out := map[string]bool{}
	loader, err := benchmark.NewBenchmarkLoader()
	if err == nil {
		for id := range loader.CISRules {
			out[id] = true
		}
		for id := range loader.Remediation {
			out[id] = true
		}
	}
	opa, err := engine.NewOPAEngine()
	if err == nil {
		for id := range opa.PolicyMetadata() {
			out[id] = true
		}
	}
	if len(out) == 0 {
		return out, fmt.Errorf("no rules loaded")
	}
	return out, nil
}

// closestRuleID returns a rule id from the known set that has the same
// prefix as the (unknown) input. Cheap heuristic, no Levenshtein.
func closestRuleID(known map[string]bool, input string) string {
	if input == "" {
		return ""
	}
	prefix := strings.ToLower(input)
	if len(prefix) > 4 {
		prefix = prefix[:4]
	}
	var matches []string
	for id := range known {
		if strings.HasPrefix(strings.ToLower(id), prefix) {
			matches = append(matches, id)
		}
	}
	if len(matches) == 0 {
		return ""
	}
	sort.Strings(matches)
	return matches[0]
}
