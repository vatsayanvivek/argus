package cmd

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/vatsayanvivek/argus/internal/collector/azure"
	"github.com/vatsayanvivek/argus/internal/drift"
)

var (
	driftSubscription string
	driftTenant       string
	driftDays         int
)

var driftCmd = &cobra.Command{
	Use:   "drift",
	Short: "Analyze IAM permission drift — granted vs actually used permissions",
	RunE:  runDrift,
}

func init() {
	driftCmd.Flags().StringVar(&driftSubscription, "subscription", "", "Azure subscription ID (required)")
	driftCmd.Flags().StringVar(&driftTenant, "tenant", "", "Azure tenant ID (required)")
	driftCmd.Flags().IntVar(&driftDays, "days", 30, "Days of Activity Log history to analyze")
	_ = driftCmd.MarkFlagRequired("subscription")
	_ = driftCmd.MarkFlagRequired("tenant")
}

func runDrift(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	collector, err := azure.NewCollector(driftSubscription, driftTenant)
	if err != nil {
		return fmt.Errorf("failed to initialize Azure collector: %w", err)
	}

	snapshot, _ := collector.CollectAll(ctx)
	if snapshot == nil {
		return fmt.Errorf("collection returned no data")
	}

	analyzer := drift.NewAnalyzer(snapshot.ActivityLog)
	driftFindings := analyzer.Analyze(snapshot, driftDays)

	if len(driftFindings) == 0 {
		fmt.Println()
		fmt.Println("  No drift findings detected (no role assignments or no Activity Log data).")
		fmt.Println()
		return nil
	}

	red := color.New(color.FgRed, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	blue := color.New(color.FgBlue).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()

	fmt.Println()
	fmt.Printf("  Permission Drift Analysis (%d identities, %d days)\n\n", len(driftFindings), driftDays)

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "  IDENTITY\tTYPE\tGRANTED\tUSED\tUNUSED %\tBLAST RADIUS")
	fmt.Fprintln(w, "  --------\t----\t-------\t----\t--------\t------------")
	for _, df := range driftFindings {
		br := df.BlastRadius
		switch br {
		case "CRITICAL":
			br = red(br)
		case "HIGH":
			br = yellow(br)
		case "MEDIUM":
			br = blue(br)
		case "LOW":
			br = green(br)
		}
		fmt.Fprintf(w, "  %s\t%s\t%d\t%d\t%.1f%%\t%s\n",
			truncate(df.IdentityName, 30),
			df.IdentityType,
			len(df.GrantedActions),
			len(df.UsedActions),
			df.UnusedPercentage,
			br,
		)
	}
	w.Flush()

	highRisk := 0
	for _, df := range driftFindings {
		if df.UnusedPercentage >= 60.0 {
			highRisk++
		}
	}
	fmt.Printf("\n  High blast radius (60%%+ unused): %s\n\n", yellow(fmt.Sprintf("%d", highRisk)))
	return nil
}
