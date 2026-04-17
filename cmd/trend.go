package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/vatsayanvivek/argus/internal/trend"
)

var (
	trendSubscription string
	trendDays         int
)

var trendCmd = &cobra.Command{
	Use:   "trend",
	Short: "Show scan history and score trend for a subscription",
	RunE:  runTrend,
}

func init() {
	trendCmd.Flags().StringVar(&trendSubscription, "subscription", "", "Azure subscription ID (required)")
	trendCmd.Flags().IntVar(&trendDays, "days", 90, "Show history for the last N days")
	_ = trendCmd.MarkFlagRequired("subscription")
}

func runTrend(cmd *cobra.Command, args []string) error {
	store := trend.NewHistoryStore()
	all, err := store.LoadAll(trendSubscription)
	if err != nil {
		return fmt.Errorf("load scan history: %w", err)
	}

	// Filter to the last `trendDays` days.
	cutoff := time.Now().AddDate(0, 0, -trendDays)
	records := make([]trend.ScanRecord, 0, len(all))
	for _, r := range all {
		if !r.ScanTime.Before(cutoff) {
			records = append(records, r)
		}
	}

	if len(records) == 0 {
		fmt.Printf("No scan history found for subscription %s. Run argus scan first.\n", trendSubscription)
		return nil
	}

	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	gray := color.New(color.FgHiBlack).SprintFunc()

	fmt.Println()
	fmt.Println(cyan(fmt.Sprintf("ARGUS Score Trend (last %d days, %d scans)", trendDays, len(records))))
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "  DATE\tSCORE\tGRADE\tFINDINGS\tCHAINS\tTREND")
	fmt.Fprintln(w, "  ----\t-----\t-----\t--------\t------\t-----")

	var prev *trend.ScanRecord
	for i := range records {
		r := records[i]
		trendCell := gray("—")
		if prev != nil {
			d := r.OverallScore - prev.OverallScore
			switch {
			case d > 2.0:
				trendCell = green(fmt.Sprintf("↑ +%.1f", d))
			case d < -2.0:
				trendCell = red(fmt.Sprintf("↓ %.1f", d))
			default:
				trendCell = gray(fmt.Sprintf("→ %+.1f", d))
			}
		}
		fmt.Fprintf(w, "  %s\t%.1f\t%s\t%d\t%d\t%s\n",
			r.ScanTime.Format("2006-01-02 15:04:05"),
			r.OverallScore, r.Grade,
			r.TotalFindings, r.ChainCount, trendCell,
		)
		prev = &records[i]
	}
	_ = w.Flush()
	fmt.Println()

	// Summary stats across the filtered window.
	var (
		sum       float64
		best      = records[0].OverallScore
		worst     = records[0].OverallScore
		maxChains = records[0].ChainCount
	)
	for _, r := range records {
		sum += r.OverallScore
		if r.OverallScore > best {
			best = r.OverallScore
		}
		if r.OverallScore < worst {
			worst = r.OverallScore
		}
		if r.ChainCount > maxChains {
			maxChains = r.ChainCount
		}
	}
	avg := sum / float64(len(records))

	fmt.Println(cyan("Summary:"))
	fmt.Printf("  Average score:            %.1f\n", avg)
	fmt.Printf("  Best score:               %.1f\n", best)
	fmt.Printf("  Worst score:              %.1f\n", worst)
	fmt.Printf("  Most chains in any scan:  %d\n", maxChains)
	fmt.Println()

	if len(records) >= 2 {
		first := records[0]
		last := records[len(records)-1]
		diff := last.OverallScore - first.OverallScore
		var label string
		switch {
		case diff > 2.0:
			label = green(fmt.Sprintf("improving by +%.1f points", diff))
		case diff < -2.0:
			label = red(fmt.Sprintf("degrading by %.1f points", diff))
		default:
			label = gray(fmt.Sprintf("stable, %+.1f points", diff))
		}
		fmt.Printf("  Trajectory: %.1f / 100 (%s over %d scans)\n\n",
			last.OverallScore, label, len(records))
	}

	return nil
}
