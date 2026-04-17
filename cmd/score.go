package cmd

import (
	"context"
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/vatsayanvivek/argus/internal/benchmark"
	"github.com/vatsayanvivek/argus/internal/collector/azure"
	"github.com/vatsayanvivek/argus/internal/engine"
	"github.com/vatsayanvivek/argus/internal/scorer"
)

var (
	scoreSubscription string
	scoreTenant       string
)

var scoreCmd = &cobra.Command{
	Use:   "score",
	Short: "Run a full scan silently and print only the score summary",
	RunE:  runScore,
}

func init() {
	scoreCmd.Flags().StringVar(&scoreSubscription, "subscription", "", "Azure subscription ID (required)")
	scoreCmd.Flags().StringVar(&scoreTenant, "tenant", "", "Azure tenant ID (required)")
	_ = scoreCmd.MarkFlagRequired("subscription")
	_ = scoreCmd.MarkFlagRequired("tenant")
}

func runScore(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	collector, err := azure.NewCollector(scoreSubscription, scoreTenant)
	if err != nil {
		return fmt.Errorf("failed to initialize Azure collector: %w", err)
	}
	snapshot, _ := collector.CollectAll(ctx)
	if snapshot == nil {
		return fmt.Errorf("snapshot collection returned nil")
	}

	loader, err := benchmark.NewBenchmarkLoader()
	if err != nil {
		return err
	}
	opaEngine, err := engine.NewOPAEngine()
	if err != nil {
		return err
	}
	findings, err := opaEngine.Evaluate(snapshot, "all")
	if err != nil {
		return err
	}
	for i := range findings {
		benchmark.EnrichFinding(&findings[i], loader)
	}

	correlator := engine.NewCorrelator()
	chains := correlator.Correlate(findings, snapshot)
	correlator.MarkChainParticipants(findings, chains)

	scoringEngine := scorer.NewScorer()
	report := scoringEngine.Score(findings, chains, snapshot)

	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	red := color.New(color.FgRed, color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	gradeColor := green
	switch report.Grade {
	case "C":
		gradeColor = yellow
	case "D", "F":
		gradeColor = red
	}

	fmt.Println()
	fmt.Printf("  ZT Score:  %s / 100   Grade: %s   Maturity: %s\n",
		cyan(fmt.Sprintf("%.2f", report.OverallScore)),
		gradeColor(report.Grade),
		report.MaturityLevel,
	)
	fmt.Println()
	fmt.Println("  Pillar Scores:")
	for name, ps := range report.PillarScores {
		fmt.Printf("    %-12s %6.2f  %-10s [%s]\n", name, ps.Score, ps.Grade, ps.TenetStatus)
	}
	fmt.Println()
	fmt.Printf("  Findings:  CRITICAL=%d  HIGH=%d  MEDIUM=%d  LOW=%d\n",
		report.FindingsBySeverity["CRITICAL"],
		report.FindingsBySeverity["HIGH"],
		report.FindingsBySeverity["MEDIUM"],
		report.FindingsBySeverity["LOW"],
	)
	fmt.Printf("  Attack chains detected: %d\n", report.ChainsDetected)
	fmt.Println()
	return nil
}
