package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"

	"github.com/vatsayanvivek/argus/internal/benchmark"
	"github.com/vatsayanvivek/argus/internal/collector/azure"
	"github.com/vatsayanvivek/argus/internal/config"
	"github.com/vatsayanvivek/argus/internal/drift"
	"github.com/vatsayanvivek/argus/internal/engine"
	"github.com/vatsayanvivek/argus/internal/models"
	"github.com/vatsayanvivek/argus/internal/pathfinder"
	"github.com/vatsayanvivek/argus/internal/reporter"
	"github.com/vatsayanvivek/argus/internal/scorer"
	"github.com/vatsayanvivek/argus/internal/suppression"
	"github.com/vatsayanvivek/argus/internal/trend"
)

var (
	scanSubscription    string
	scanTenant          string
	scanCompliance      string
	scanOutput          string
	scanOutputDir       string
	scanDrift           bool
	scanEvidence        bool
	scanOrgWide         bool
	scanManagementGroup string
	scanSuppressFile    string
	scanShowSuppressed  bool
	scanCI              bool
	scanCICritThreshold int
	scanCIChainThreshold int
	scanCIMinScore      float64
	scanDiscoverChains   bool
)

// CIGateError is returned when a CI gate check fails. It carries a
// specific exit code (typically 2) so the root command can propagate it
// to the process exit status, distinguishing gate failures from runtime
// errors.
type CIGateError struct {
	Message  string
	ExitCode int
}

func (e *CIGateError) Error() string {
	return e.Message
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a full attack chain analysis scan against an Azure subscription",
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVar(&scanSubscription, "subscription", "", "Azure subscription ID (required unless --org-wide)")
	scanCmd.Flags().StringVar(&scanTenant, "tenant", "", "Azure tenant ID (required)")
	scanCmd.Flags().StringVar(&scanCompliance, "compliance", "all", "Compliance filter: cis-azure-2.0|nist-800-207|nist-800-53|soc2|hipaa|pci-dss-4|iso-27001|all")
	scanCmd.Flags().StringVar(&scanOutput, "output", "all", "Output format: html|json|sarif|all")
	scanCmd.Flags().StringVar(&scanOutputDir, "output-dir", "./argus-output", "Output directory")
	scanCmd.Flags().BoolVar(&scanDrift, "drift", false, "Enable behavioral drift analysis")
	scanCmd.Flags().BoolVar(&scanEvidence, "evidence", false, "Generate compliance evidence bundle zip")
	scanCmd.Flags().BoolVar(&scanOrgWide, "org-wide", false, "Discover and scan every Enabled subscription in the tenant in parallel")
	scanCmd.Flags().StringVar(&scanManagementGroup, "management-group", "", "Restrict --org-wide to subscriptions under this management group")
	scanCmd.Flags().StringVar(&scanSuppressFile, "suppress-file", ".argusignore", "Path to suppression file")
	scanCmd.Flags().BoolVar(&scanShowSuppressed, "show-suppressed", false, "Include suppressed findings in main results (still annotated)")
	scanCmd.Flags().BoolVar(&scanCI, "ci", false, "Enable CI/CD gate mode (exit code 2 on gate failure)")
	scanCmd.Flags().IntVar(&scanCICritThreshold, "ci-critical-threshold", 0, "Fail if CRITICAL findings >= N (0 = fail on any critical)")
	scanCmd.Flags().IntVar(&scanCIChainThreshold, "ci-chain-threshold", 0, "Fail if CRITICAL chains >= N (0 = fail on any critical chain)")
	scanCmd.Flags().Float64Var(&scanCIMinScore, "ci-min-score", 0, "Fail if ZT score < N")
	scanCmd.Flags().BoolVar(&scanDiscoverChains, "discover-chains", true, "Run graph-based pathfinder to surface attack chains missed by the 51 hand-authored patterns (DISC-*)")
	_ = scanCmd.MarkFlagRequired("tenant")
}

func runScan(cmd *cobra.Command, args []string) error {
	if !scanOrgWide && scanSubscription == "" {
		return fmt.Errorf("--subscription is required (or use --org-wide to scan every Enabled subscription)")
	}
	if err := os.MkdirAll(scanOutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Load config file and apply CI gate defaults. CLI flags override
	// config file values; config file values override built-in defaults.
	cfg, cfgErr := config.LoadConfig()
	if cfgErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load config file: %v\n", cfgErr)
	}
	applyCIConfigDefaults(cmd, cfg)

	// Load suppressions once. Missing file is fine and yields an empty list.
	supList, err := suppression.LoadSuppressions(scanSuppressFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to parse suppression file %s: %v\n", scanSuppressFile, err)
		supList = &suppression.SuppressionList{}
	}
	if warnings := supList.Warnings(); len(warnings) > 0 {
		yellow := color.New(color.FgYellow).SprintFunc()
		for _, w := range warnings {
			fmt.Fprintln(os.Stderr, yellow("[suppression] ")+w)
		}
	}

	if scanOrgWide {
		return runOrgWideScan(supList)
	}
	return runSingleSubscriptionScan(scanSubscription, scanTenant, supList, true)
}

// applyCIConfigDefaults merges CI gate settings from the config file
// into the scan flags. Config values are used only when the
// corresponding CLI flag was not explicitly set by the user.
func applyCIConfigDefaults(cmd *cobra.Command, cfg *config.Config) {
	if cfg == nil {
		return
	}
	gates := cfg.CIGates

	// If config enables CI mode and --ci was not passed on CLI, adopt it.
	if gates.Enabled && !cmd.Flags().Changed("ci") {
		scanCI = true
	}

	if !scanCI {
		return
	}

	if !cmd.Flags().Changed("ci-critical-threshold") && gates.CriticalThreshold > 0 {
		scanCICritThreshold = gates.CriticalThreshold
	}
	if !cmd.Flags().Changed("ci-chain-threshold") && gates.HighChainThreshold > 0 {
		scanCIChainThreshold = gates.HighChainThreshold
	}
	if !cmd.Flags().Changed("ci-min-score") && gates.MinScore > 0 {
		scanCIMinScore = gates.MinScore
	}
}

func runSingleSubscriptionScan(
	subscriptionID string,
	tenantID string,
	supList *suppression.SuppressionList,
	verbose bool,
) error {
	ctx := context.Background()
	timestamp := time.Now().UTC().Format("20060102_150405")

	// Branded banner so the CLI feels like a real product, not a raw
	// Cobra default. Only shown in interactive terminals; piped use
	// (CI, JSON processing) gets a clean stdout.
	if verbose {
		PrintBanner(os.Stdout)
	}

	// --- Preflight: fail fast with a clear message instead of a 60s hang ---
	//
	// Enterprise users often hit corporate proxy / Defender Network
	// Inspection / Zscaler-style CASB that silently blocks Azure
	// endpoints. Without a preflight, the SDK times out after ~60s
	// with "context deadline exceeded" — the worst possible UX.
	//
	// Preflight probes the three endpoints we actually use (ARM,
	// Graph, login) with a 5-second-per-endpoint timeout and
	// diagnoses the failure pattern (DNS / proxy / TLS / firewall /
	// Defender network inspection) so the user knows what to fix.
	if verbose {
		fmt.Println("Preflight: checking connectivity to Azure...")
	}
	pf := azure.Preflight(ctx)
	if !pf.OK {
		printPreflightReport(pf)
		return fmt.Errorf("preflight connectivity check failed — see diagnosis above")
	}
	if verbose {
		fmt.Printf("✓ Azure reachable (%s)\n", pf.TotalElapsed.Round(10*time.Millisecond))
	}
	if err := azure.PreflightAuth(ctx); err != nil {
		return err
	}
	if verbose {
		fmt.Println("✓ Azure credentials valid")
	}

	// 1. Authenticate + initialize collector
	collector, err := azure.NewCollector(subscriptionID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to initialize Azure collector: %w", err)
	}

	// Live per-collector status replaces the old 7-step progress bar
	// that froze at 14% during the parallel CollectAll phase. Users
	// now see every sub-collector transition pending → running → done
	// with elapsed times, so they never wonder whether the scan is
	// stuck.
	renderer := newScanProgressRenderer(os.Stdout)
	renderer.Start()

	// The post-collection steps (OPA, chain correlation, report
	// generation) still need a small progress bar so users see
	// forward motion through those phases. Keep it compact.
	bar := progressbar.NewOptions(3,
		progressbar.OptionSetDescription("Evaluating policies..."),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(40),
		progressbar.OptionEnableColorCodes(true),
	)

	// 2-4. Collect everything (one CollectAll runs collectors in parallel)
	snapshot, err := collector.CollectAllWithProgress(ctx, renderer.OnEvent)
	renderer.Done()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: collection completed with errors: %v\n", err)
	}
	if snapshot == nil {
		// Build minimal snapshot so we still produce a report
		snapshot = &models.AzureSnapshot{
			SubscriptionID: subscriptionID,
			TenantID:       tenantID,
			ScanTime:       time.Now().UTC(),
			CollectionMode: "minimal",
		}
	}
	// 5. Evaluate OPA policies — count dynamically so the banner
	// always reflects the current rule library size.
	loader, err := benchmark.NewBenchmarkLoader()
	if err != nil {
		return fmt.Errorf("failed to load benchmark data: %w", err)
	}
	opaEngine, err := engine.NewOPAEngine()
	if err != nil {
		return fmt.Errorf("failed to initialize OPA engine: %w", err)
	}
	srcCounts := opaEngine.RuleCountBySource()
	bar.Describe(fmt.Sprintf("Evaluating %d policies (%d CIS + %d ZT)...",
		opaEngine.RuleCount(),
		srcCounts["argus-cis"],
		srcCounts["argus-zt"],
	))
	allFindings, err := opaEngine.Evaluate(snapshot, scanCompliance)
	if err != nil {
		return fmt.Errorf("policy evaluation failed: %w", err)
	}
	for i := range allFindings {
		benchmark.EnrichFinding(&allFindings[i], loader)
	}

	// Apply suppressions. The active list goes downstream to chains
	// and scoring; the suppressed list is reported separately so the
	// audit trail remains intact.
	var findings, suppressedFindings []models.Finding
	if scanShowSuppressed {
		_, suppressedFindings = supList.FilterFindings(allFindings)
		findings = allFindings
	} else {
		findings, suppressedFindings = supList.FilterFindings(allFindings)
	}
	if verbose && len(suppressedFindings) > 0 {
		fmt.Fprintf(os.Stderr, "[suppression] %d finding(s) suppressed via %s\n", len(suppressedFindings), scanSuppressFile)
	}
	_ = bar.Add(1)

	// 6. Correlate attack chains — hand-authored patterns first, then
	// graph-based discovered paths appended.
	bar.Describe("Correlating attack chains...")
	correlator := engine.NewCorrelator()
	chains := correlator.Correlate(findings, snapshot)
	correlator.MarkChainParticipants(findings, chains)
	if scanDiscoverChains {
		discovered := pathfinder.DiscoverChains(snapshot, findings)
		chains = append(chains, discovered...)
	}
	_ = bar.Add(1)

	// Score
	scoringEngine := scorer.NewScorer()
	scoreReport := scoringEngine.Score(findings, chains, snapshot)

	// Pareto remediation roadmap — top 5 fixes by chain-break + score impact.
	quickWins := scorer.ComputeQuickWins(findings, chains, snapshot, loader, 5)

	// Build a ScanRecord and persist for trend analysis. Load previous
	// scan to compute the delta which is then passed to the reporters.
	historyStore := trend.NewHistoryStore()
	scanRecord := trend.BuildScanRecord(
		snapshot.SubscriptionID,
		snapshot.SubscriptionName,
		findings,
		chains,
		scoreReport,
	)
	previousScan, _ := historyStore.LoadPrevious(snapshot.SubscriptionID, scanRecord.ScanID)
	trendReport := trend.ComputeTrendDetailed(scanRecord, previousScan, findings)
	if err := historyStore.Save(scanRecord); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to persist scan history: %v\n", err)
	}

	// Optional: drift
	var driftFindings []models.DriftFinding
	if scanDrift {
		analyzer := drift.NewAnalyzer(snapshot.ActivityLog)
		driftFindings = analyzer.Analyze(snapshot, 30)
	}

	// 7. Generate reports
	bar.Describe("Generating report...")
	reportPaths := []string{}

	if scanOutput == "html" || scanOutput == "all" {
		htmlPath := filepath.Join(scanOutputDir, fmt.Sprintf("argus_%s.html", timestamp))
		htmlReporter := reporter.NewHTMLReporter()
		htmlReporter.SetVersion(version)
		htmlReporter.SetTrendReport(trendReport)
		htmlReporter.SetQuickWins(quickWins)
		htmlReporter.SetGraphPermissionsWarning(snapshot.GraphPermissionsLimited, snapshot.GraphPermissionsMissing)
		if err := htmlReporter.Generate(snapshot, findings, chains, scoreReport, driftFindings, htmlPath); err != nil {
			fmt.Fprintf(os.Stderr, "HTML report generation failed: %v\n", err)
		} else {
			reportPaths = append(reportPaths, htmlPath)
		}
	}

	if scanOutput == "json" || scanOutput == "all" {
		jsonPath := filepath.Join(scanOutputDir, fmt.Sprintf("argus_%s.json", timestamp))
		jsonReporter := reporter.NewJSONReporter()
		jsonReporter.SetQuickWins(quickWins)
		jsonReporter.SetGraphPermissionsWarning(snapshot.GraphPermissionsLimited, snapshot.GraphPermissionsMissing)
		// Build one CoverageReport per loaded compliance framework and
		// attach the collection to the JSON output. The reporter is
		// agnostic to framework identities — it carries the map through
		// unchanged — so adding a new pack requires only a new JSON
		// file under policies/compliance/, no reporter change.
		if coverage := buildComplianceCoverage(opaEngine, findings); len(coverage) > 0 {
			jsonReporter.SetComplianceCoverage(coverage)
		}
		if err := jsonReporter.Generate(snapshot, findings, chains, scoreReport, driftFindings, jsonPath); err != nil {
			fmt.Fprintf(os.Stderr, "JSON report generation failed: %v\n", err)
		} else {
			reportPaths = append(reportPaths, jsonPath)
		}
	}

	if scanOutput == "sarif" || scanOutput == "all" {
		sarifPath := filepath.Join(scanOutputDir, fmt.Sprintf("argus_%s.sarif", timestamp))
		sarifReporter := reporter.NewSARIFReporter()
		if err := sarifReporter.Generate(findings, sarifPath); err != nil {
			fmt.Fprintf(os.Stderr, "SARIF report generation failed: %v\n", err)
		} else {
			reportPaths = append(reportPaths, sarifPath)
		}
	}

	if scanEvidence {
		evidenceGen := reporter.NewEvidenceGenerator()
		evidencePath, err := evidenceGen.Generate(snapshot, findings, chains, scoreReport, driftFindings, scanOutputDir, timestamp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Evidence bundle generation failed: %v\n", err)
		} else {
			reportPaths = append(reportPaths, evidencePath)
		}
	}
	_ = bar.Add(1)
	_ = bar.Finish()
	fmt.Println()

	// Print summary box (only in interactive single-sub mode).
	if verbose {
		printSummary(snapshot, scoreReport, chains, findings, driftFindings, suppressedFindings, reportPaths, trendReport, opaEngine.RuleCount(), srcCounts["argus-cis"], srcCounts["argus-zt"])
	}

	// CI/CD gate evaluation — run after all reports are generated so
	// artifacts are always available regardless of pass/fail.
	if scanCI {
		if gateErr := evaluateCIGates(scoreReport, chains); gateErr != nil {
			return gateErr
		}
	}

	return nil
}

func printSummary(
	snapshot *models.AzureSnapshot,
	scoreReport *models.ZTScoreReport,
	chains []models.AttackChain,
	findings []models.Finding,
	driftFindings []models.DriftFinding,
	suppressedFindings []models.Finding,
	reportPaths []string,
	trendReport *trend.TrendReport,
	ruleCount int,
	cisCount int,
	ztCount int,
) {
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	red := color.New(color.FgRed, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()

	gradeColor := green
	switch scoreReport.Grade {
	case "C":
		gradeColor = yellow
	case "D", "F":
		gradeColor = red
	}

	criticalChains := scoreReport.ChainsBySeverity["CRITICAL"]
	highChains := scoreReport.ChainsBySeverity["HIGH"]

	subName := snapshot.SubscriptionName
	if subName == "" {
		subName = snapshot.SubscriptionID
	}

	// Loud Microsoft Graph permissions warning. This is critical
	// because without admin Graph scopes, several identity rules
	// (notably CHAIN-002, App Registration high-privilege Graph
	// permissions) cannot be evaluated and the user might walk away
	// thinking they're safe when they haven't even been checked.
	if snapshot.GraphPermissionsLimited {
		fmt.Println()
		fmt.Println(red("⚠️  ═══════════════════════════════════════════════════════════"))
		fmt.Println(red("⚠️   LIMITED MICROSOFT GRAPH ACCESS"))
		fmt.Println(red("⚠️  ═══════════════════════════════════════════════════════════"))
		fmt.Println(yellow("⚠️   The scanning identity does not have full Microsoft Graph"))
		fmt.Println(yellow("⚠️   access. The following rules COULD NOT be evaluated:"))
		fmt.Println(yellow("⚠️"))
		fmt.Println(yellow("⚠️     • zt_id_011 / cis_1_15  — App Registration high-priv perms"))
		fmt.Println(yellow("⚠️     • zt_id_003 / zt_id_007 — PIM analysis"))
		fmt.Println(yellow("⚠️     • zt_id_004 / zt_id_006 — Conditional Access policies"))
		fmt.Println(yellow("⚠️     • zt_id_010              — Access reviews"))
		fmt.Println(yellow("⚠️"))
		fmt.Println(yellow("⚠️   This means CHAIN-002 (App Registration takeover) is NOT being checked."))
		fmt.Println(yellow("⚠️"))
		fmt.Print(yellow("⚠️   Missing scopes: "))
		fmt.Println(red(strings.Join(snapshot.GraphPermissionsMissing, ", ")))
		fmt.Println(yellow("⚠️"))
		fmt.Println(yellow("⚠️   Fix: run scripts/setup-graph-permissions.sh and re-scan."))
		fmt.Println(red("⚠️  ═══════════════════════════════════════════════════════════"))
		fmt.Println()
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║      ARGUS — Blindspot & Attack Chain Analysis   ║")
	fmt.Println("╠══════════════════════════════════════════════════╣")
	fmt.Printf("║  Subscription:  %-32s ║\n", truncate(subName, 32))
	fmt.Printf("║  Resources:     %d scanned%s║\n", scoreReport.ResourcesScanned, padding(scoreReport.ResourcesScanned, 25))
	fmt.Printf("║  ZT Score:      %s / 100    Grade: %s            ║\n", cyan(fmt.Sprintf("%.1f", scoreReport.OverallScore)), gradeColor(scoreReport.Grade))
	fmt.Printf("║  Maturity:      %-32s ║\n", scoreReport.MaturityLevel)
	fmt.Println("╠══════════════════════════════════════════════════╣")
	// Display unique resources first (the actionable count) and rule
	// violations second (the raw count). Two rules firing on the same
	// resource = ONE problem, not two.
	uc := scoreReport.UniqueCriticalResources
	uh := scoreReport.UniqueHighResources
	rc := scoreReport.FindingsBySeverity["CRITICAL"]
	rh := scoreReport.FindingsBySeverity["HIGH"]
	fmt.Printf("║  CRITICAL:      %s unique resources (%d violations)%s║\n",
		red(fmt.Sprintf("%d", uc)), rc, padding(uc+rc, 9))
	fmt.Printf("║  HIGH:          %s unique resources (%d violations)%s║\n",
		yellow(fmt.Sprintf("%d", uh)), rh, padding(uh+rh, 9))
	fmt.Printf("║  MEDIUM:        %d unique resources (%d violations)%s║\n",
		scoreReport.UniqueMediumResources, scoreReport.FindingsBySeverity["MEDIUM"],
		padding(scoreReport.UniqueMediumResources+scoreReport.FindingsBySeverity["MEDIUM"], 9))
	fmt.Printf("║  LOW:           %d unique resources (%d violations)%s║\n",
		scoreReport.UniqueLowResources, scoreReport.FindingsBySeverity["LOW"],
		padding(scoreReport.UniqueLowResources+scoreReport.FindingsBySeverity["LOW"], 9))
	fmt.Println("╠══════════════════════════════════════════════════╣")
	fmt.Printf("║  Attack Chains Detected:  %s                       ║\n", red(fmt.Sprintf("%d", len(chains))))
	fmt.Printf("║    CRITICAL chains:  %d                            ║\n", criticalChains)
	fmt.Printf("║    HIGH chains:      %d                            ║\n", highChains)
	fmt.Println("╠══════════════════════════════════════════════════╣")
	// Ruleset count lines — widths fit the 50-col box.
	fmt.Printf("║  CIS Azure v2.0:  %-3d checks%s║\n", cisCount, padding(len(fmt.Sprintf("%d", cisCount))+22, 23))
	fmt.Printf("║  ARGUS ZT Rules:  %-3d checks%s║\n", ztCount, padding(len(fmt.Sprintf("%d", ztCount))+22, 23))
	fmt.Printf("║  Total evaluated: %-3d checks%s║\n", ruleCount, padding(len(fmt.Sprintf("%d", ruleCount))+22, 23))
	if len(driftFindings) > 0 {
		fmt.Println("╠══════════════════════════════════════════════════╣")
		fmt.Printf("║  Drift findings:  %d identities%s║\n", len(driftFindings), padding(len(driftFindings), 18))
	}
	if len(suppressedFindings) > 0 {
		fmt.Println("╠══════════════════════════════════════════════════╣")
		fmt.Printf("║  Suppressed:      %d finding(s) via .argusignore%s║\n",
			len(suppressedFindings), padding(len(suppressedFindings), 7))
	}
	if trendReport != nil && trendReport.HasPrevious && trendReport.PreviousScan != nil {
		prev := trendReport.PreviousScan
		prevDate := prev.ScanTime.Format("2006-01-02")
		deltaSign := "+"
		if trendReport.ScoreDelta < 0 {
			deltaSign = ""
		}
		trendLabel := trendReport.Trend
		switch trendReport.Trend {
		case "IMPROVING":
			trendLabel = green("IMPROVING")
		case "DEGRADING":
			trendLabel = red("DEGRADING")
		default:
			trendLabel = yellow("STABLE")
		}
		fmt.Println("╠══════════════════════════════════════════════════╣")
		fmt.Printf("║  Trend vs previous scan (%s):%s║\n",
			prevDate, padding(0, 22-len(prevDate)))
		fmt.Printf("║  Score: %.1f → %.1f  (%s%.1f)  %-18s ║\n",
			prev.OverallScore, scoreReport.OverallScore,
			deltaSign, trendReport.ScoreDelta, trendLabel)
		fmt.Printf("║  New findings:      %d%s║\n",
			len(trendReport.NewFindings), padding(len(trendReport.NewFindings), 28))
		fmt.Printf("║  Resolved findings: %d%s║\n",
			len(trendReport.ResolvedFindings), padding(len(trendReport.ResolvedFindings), 28))
		fmt.Printf("║  New chains:        %d%s║\n",
			len(trendReport.NewChains), padding(len(trendReport.NewChains), 28))
		fmt.Printf("║  Resolved chains:   %d%s║\n",
			len(trendReport.ResolvedChains), padding(len(trendReport.ResolvedChains), 28))
	}
	fmt.Println("╠══════════════════════════════════════════════════╣")
	for _, p := range reportPaths {
		fmt.Printf("║  Report: %-39s ║\n", truncate(p, 39))
	}
	fmt.Println("╚══════════════════════════════════════════════════╝")

	// Scope breakdown below the box — some tenants produce enough
	// findings that fitting this line inside the 50-col banner warps
	// the border, so print it outside where it can flow naturally.
	scopeCounts := map[string]int{}
	for _, f := range findings {
		scopeCounts[f.Scope]++
	}
	fmt.Printf("  Findings by scope: resource=%d  resource-group=%d  subscription=%d  tenant=%d\n",
		scopeCounts[models.ScopeResource],
		scopeCounts[models.ScopeResourceGroup],
		scopeCounts[models.ScopeSubscription],
		scopeCounts[models.ScopeTenant],
	)
}

// evaluateCIGates checks scan results against the configured CI gate
// thresholds. If any gate fails, it prints a summary banner and returns
// a CIGateError with exit code 2. If all gates pass, it prints a PASS
// banner and returns nil.
func evaluateCIGates(scoreReport *models.ZTScoreReport, chains []models.AttackChain) *CIGateError {
	red := color.New(color.FgRed, color.Bold).SprintFunc()
	green := color.New(color.FgGreen, color.Bold).SprintFunc()

	var failures []string

	// Gate 1: critical findings count.
	criticalFindings := scoreReport.FindingsBySeverity["CRITICAL"]
	if criticalFindings > scanCICritThreshold {
		failures = append(failures, fmt.Sprintf("%d CRITICAL findings (threshold: %d)", criticalFindings, scanCICritThreshold))
	}

	// Gate 2: critical chains count.
	criticalChains := scoreReport.ChainsBySeverity["CRITICAL"]
	if criticalChains > scanCIChainThreshold {
		failures = append(failures, fmt.Sprintf("%d CRITICAL chains (threshold: %d)", criticalChains, scanCIChainThreshold))
	}

	// Gate 3: minimum score.
	if scanCIMinScore > 0 && scoreReport.OverallScore < scanCIMinScore {
		failures = append(failures, fmt.Sprintf("score %.1f below minimum %.1f", scoreReport.OverallScore, scanCIMinScore))
	}

	fmt.Println()
	if len(failures) > 0 {
		// Find the longest reason line so we can size the box.
		header := "  CI GATE: FAIL"
		maxLen := len(header)
		for _, f := range failures {
			line := fmt.Sprintf("  Reason: %s", f)
			if len(line) > maxLen {
				maxLen = len(line)
			}
		}
		boxWidth := maxLen + 4 // 2 padding + 2 border chars
		if boxWidth < 44 {
			boxWidth = 44
		}

		border := strings.Repeat("=", boxWidth-2)
		fmt.Printf("%s\n", red(fmt.Sprintf("\u2554%s\u2557", border)))
		fmt.Printf("%s\n", red(fmt.Sprintf("\u2551  CI GATE: FAIL%s\u2551", strings.Repeat(" ", boxWidth-17))))
		for _, f := range failures {
			line := fmt.Sprintf("  Reason: %s", f)
			fmt.Printf("%s\n", red(fmt.Sprintf("\u2551%s%s\u2551", line, strings.Repeat(" ", boxWidth-2-len(line)))))
		}
		fmt.Printf("%s\n", red(fmt.Sprintf("\u255a%s\u255d", border)))
		fmt.Println()

		return &CIGateError{
			Message:  fmt.Sprintf("CI gate failed: %s", strings.Join(failures, "; ")),
			ExitCode: 2,
		}
	}

	boxWidth := 44
	border := strings.Repeat("=", boxWidth-2)
	fmt.Printf("%s\n", green(fmt.Sprintf("\u2554%s\u2557", border)))
	fmt.Printf("%s\n", green(fmt.Sprintf("\u2551  CI GATE: PASS%s\u2551", strings.Repeat(" ", boxWidth-17))))
	fmt.Printf("%s\n", green(fmt.Sprintf("\u255a%s\u255d", border)))
	fmt.Println()

	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func padding(value int, totalWidth int) string {
	digits := 1
	for v := value; v >= 10; v /= 10 {
		digits++
	}
	pad := totalWidth - digits
	if pad < 1 {
		pad = 1
	}
	out := ""
	for i := 0; i < pad; i++ {
		out += " "
	}
	return out
}

// runOrgWideScan discovers every Enabled subscription in the tenant
// (optionally restricted to a management group) and runs the per-sub
// pipeline in parallel with a bounded worker pool. After every scan
// finishes it builds a tenant rollup view that surfaces the worst
// subscriptions, total chains across the tenant, and an aggregated
// score.
func runOrgWideScan(supList *suppression.SuppressionList) error {
	ctx := context.Background()
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	red := color.New(color.FgRed, color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()

	fmt.Println(cyan("[org-wide] Discovering subscriptions..."))

	// We need a credential to call the management plane. Build a
	// throwaway collector with a placeholder subscription ID just to
	// share the auth chain with subscriptions.go.
	bootstrap, err := azure.NewCollector("00000000-0000-0000-0000-000000000000", scanTenant)
	if err != nil {
		return fmt.Errorf("failed to initialise credential: %w", err)
	}

	var subs []azure.Subscription
	if scanManagementGroup != "" {
		subs, err = azure.ListSubscriptionsUnderManagementGroup(ctx, bootstrap.Credential(), scanManagementGroup)
	} else {
		subs, err = azure.ListSubscriptions(ctx, bootstrap.Credential())
	}
	if err != nil {
		return fmt.Errorf("failed to list subscriptions: %w", err)
	}
	if len(subs) == 0 {
		return fmt.Errorf("no Enabled subscriptions discovered (check Reader access on the tenant)")
	}

	fmt.Printf("%s discovered %s subscription(s):\n", cyan("[org-wide]"), cyan(fmt.Sprintf("%d", len(subs))))
	for _, s := range subs {
		fmt.Printf("    - %s  %s\n", s.ID, s.Name)
	}
	fmt.Println()

	// Bounded parallel scan.
	const maxParallel = 5
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	results := make([]models.SubscriptionScanResult, len(subs))

	for i, sub := range subs {
		wg.Add(1)
		go func(idx int, s azure.Subscription) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fmt.Printf("%s scanning %s ...\n", cyan("[org-wide]"), s.Name)
			result, err := runSubscriptionForRollup(ctx, s, supList)
			if err != nil {
				fmt.Printf("%s scan of %s failed: %v\n", red("[org-wide]"), s.Name, err)
				results[idx] = models.SubscriptionScanResult{
					SubscriptionID:   s.ID,
					SubscriptionName: s.Name,
					Error:            err.Error(),
				}
				return
			}
			fmt.Printf("%s %s done — score %.1f grade %s\n",
				green("[org-wide]"), s.Name, result.Score.OverallScore, result.Score.Grade)
			results[idx] = result
		}(i, sub)
	}
	wg.Wait()

	// Aggregate
	rollup := buildRollup(scanTenant, results)

	// Persist a tenant-rollup JSON for downstream pipelines
	timestamp := time.Now().UTC().Format("20060102_150405")
	rollupJSONPath := filepath.Join(scanOutputDir, fmt.Sprintf("argus_tenant_rollup_%s.json", timestamp))
	if err := writeRollupJSON(rollup, rollupJSONPath); err != nil {
		fmt.Fprintf(os.Stderr, "rollup JSON generation failed: %v\n", err)
	}

	printRollupSummary(rollup, rollupJSONPath)
	return nil
}

// runSubscriptionForRollup is the per-subscription pipeline used by
// the org-wide runner. It mirrors runSingleSubscriptionScan but
// returns a SubscriptionScanResult instead of writing per-sub reports
// or printing a per-sub summary.
func runSubscriptionForRollup(
	ctx context.Context,
	sub azure.Subscription,
	supList *suppression.SuppressionList,
) (models.SubscriptionScanResult, error) {
	collector, err := azure.NewCollector(sub.ID, sub.TenantID)
	if err != nil {
		return models.SubscriptionScanResult{}, err
	}
	snapshot, _ := collector.CollectAll(ctx)
	if snapshot == nil {
		snapshot = &models.AzureSnapshot{
			SubscriptionID: sub.ID,
			TenantID:       sub.TenantID,
			ScanTime:       time.Now().UTC(),
			CollectionMode: "minimal",
		}
	}
	if snapshot.SubscriptionName == "" {
		snapshot.SubscriptionName = sub.Name
	}

	loader, err := benchmark.NewBenchmarkLoader()
	if err != nil {
		return models.SubscriptionScanResult{}, err
	}
	opaEngine, err := engine.NewOPAEngine()
	if err != nil {
		return models.SubscriptionScanResult{}, err
	}
	all, err := opaEngine.Evaluate(snapshot, scanCompliance)
	if err != nil {
		return models.SubscriptionScanResult{}, err
	}
	for i := range all {
		benchmark.EnrichFinding(&all[i], loader)
	}
	findings, _ := supList.FilterFindings(all)

	correlator := engine.NewCorrelator()
	chains := correlator.Correlate(findings, snapshot)
	correlator.MarkChainParticipants(findings, chains)
	if scanDiscoverChains {
		chains = append(chains, pathfinder.DiscoverChains(snapshot, findings)...)
	}

	scoreReport := scorer.NewScorer().Score(findings, chains, snapshot)

	historyStore := trend.NewHistoryStore()
	rec := trend.BuildScanRecord(sub.ID, sub.Name, findings, chains, scoreReport)
	_ = historyStore.Save(rec)

	return models.SubscriptionScanResult{
		SubscriptionID:   sub.ID,
		SubscriptionName: sub.Name,
		Findings:         findings,
		Chains:           chains,
		Score:            scoreReport,
	}, nil
}

// buildRollup aggregates per-subscription results into the tenant view.
func buildRollup(tenantID string, results []models.SubscriptionScanResult) *models.TenantRollupReport {
	r := &models.TenantRollupReport{
		TenantID:            tenantID,
		ScanTime:            time.Now().UTC(),
		TotalSubscriptions:  len(results),
		SubscriptionResults: results,
		FindingsBySeverity:  map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
	}
	if len(results) == 0 {
		return r
	}

	var sumScore float64
	var scored int
	worstScore := 1e9
	bestScore := -1.0
	for _, sr := range results {
		if sr.Score == nil {
			continue
		}
		sumScore += sr.Score.OverallScore
		scored++
		if sr.Score.OverallScore < worstScore {
			worstScore = sr.Score.OverallScore
			r.WorstSubscription = sr.SubscriptionName
		}
		if sr.Score.OverallScore > bestScore {
			bestScore = sr.Score.OverallScore
			r.BestSubscription = sr.SubscriptionName
		}
		for sev, n := range sr.Score.FindingsBySeverity {
			r.FindingsBySeverity[sev] += n
		}
		r.TotalChains += len(sr.Chains)
		for _, c := range sr.Chains {
			if c.Severity == "CRITICAL" {
				r.CriticalChainCount++
			}
		}
	}
	if scored > 0 {
		r.TenantOverallScore = sumScore / float64(scored)
	}
	r.TenantGrade = gradeFromScore(r.TenantOverallScore)

	sort.SliceStable(r.SubscriptionResults, func(i, j int) bool {
		return scoreOrZero(r.SubscriptionResults[i]) < scoreOrZero(r.SubscriptionResults[j])
	})
	return r
}

func scoreOrZero(s models.SubscriptionScanResult) float64 {
	if s.Score == nil {
		return 0
	}
	return s.Score.OverallScore
}

func gradeFromScore(score float64) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

// writeRollupJSON serialises the tenant rollup report to disk so other
// tools (dashboards, CI scripts) can consume it.
func writeRollupJSON(r *models.TenantRollupReport, path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func printRollupSummary(r *models.TenantRollupReport, reportPath string) {
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	red := color.New(color.FgRed, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()

	gradeColor := green
	switch r.TenantGrade {
	case "C":
		gradeColor = yellow
	case "D", "F":
		gradeColor = red
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║         ARGUS — Tenant-Wide Analysis             ║")
	fmt.Println("╠══════════════════════════════════════════════════╣")
	fmt.Printf("║  Tenant:          %-32s ║\n", truncate(r.TenantID, 32))
	fmt.Printf("║  Subscriptions:   %d scanned%s║\n", r.TotalSubscriptions, padding(r.TotalSubscriptions, 24))
	fmt.Printf("║  Tenant Score:    %s / 100    Grade: %s         ║\n",
		cyan(fmt.Sprintf("%.1f", r.TenantOverallScore)), gradeColor(r.TenantGrade))
	fmt.Println("╠══════════════════════════════════════════════════╣")
	fmt.Println("║  Subscription Scores (worst → best):             ║")
	for _, sr := range r.SubscriptionResults {
		var line string
		if sr.Score == nil {
			line = fmt.Sprintf("    %s  ERROR", truncate(sr.SubscriptionName, 22))
		} else {
			line = fmt.Sprintf("    %s %.1f  Grade: %s  Chains: %d",
				truncate(sr.SubscriptionName, 18), sr.Score.OverallScore, sr.Score.Grade, len(sr.Chains))
		}
		fmt.Printf("║  %-48s ║\n", truncate(line, 48))
	}
	fmt.Println("╠══════════════════════════════════════════════════╣")
	fmt.Printf("║  Total CRITICAL:  %d findings%s║\n",
		r.FindingsBySeverity["CRITICAL"], padding(r.FindingsBySeverity["CRITICAL"], 23))
	fmt.Printf("║  Total HIGH:      %d findings%s║\n",
		r.FindingsBySeverity["HIGH"], padding(r.FindingsBySeverity["HIGH"], 23))
	fmt.Printf("║  Total Chains:    %d detected%s║\n", r.TotalChains, padding(r.TotalChains, 23))
	fmt.Printf("║  CRITICAL chains: %d%s║\n", r.CriticalChainCount, padding(r.CriticalChainCount, 31))
	if reportPath != "" {
		fmt.Println("╠══════════════════════════════════════════════════╣")
		fmt.Printf("║  Rollup: %-39s ║\n", truncate(reportPath, 39))
	}
	fmt.Println("╚══════════════════════════════════════════════════╝")
}


// buildComplianceCoverage computes a compliance coverage report for
// every compliance framework the engine has loaded, against the
// findings produced by the current scan. The return value maps
// framework short name → *engine.CoverageReport. An empty map means
// no compliance packs are loaded (or the engine is nil), in which
// case the JSON report simply omits the compliance_coverage block.
//
// This helper is intentionally read-only — it never mutates findings.
// A finding's ComplianceMappings field is set at Evaluate time and
// merely consulted here when building per-control fire counts.
func buildComplianceCoverage(eng *engine.OPAEngine, findings []models.Finding) map[string]interface{} {
	if eng == nil {
		return nil
	}
	firedByRule := map[string]bool{}
	severityByRule := map[string]string{}
	for _, f := range findings {
		firedByRule[f.ID] = true
		// Keep the highest severity observed per rule (CRITICAL > HIGH
		// > MEDIUM > LOW). "first write wins" is not good enough
		// because CollapseDuplicates may have reduced multiple
		// findings to one, and a rule can fire at different severities
		// for different resources.
		cur := severityByRule[f.ID]
		if cur == "" || severityOrder(f.Severity) < severityOrder(cur) {
			severityByRule[f.ID] = f.Severity
		}
	}
	out := map[string]interface{}{}
	for _, fw := range eng.CompliancePackFrameworks() {
		if rep := eng.BuildCoverageReport(fw, firedByRule, severityByRule); rep != nil {
			out[fw] = rep
		}
	}
	return out
}

// severityOrder mirrors engine.severityRank2 but is local to cmd so
// scan.go does not have to import an unexported helper.
func severityOrder(s string) int {
	switch strings.ToUpper(s) {
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

// printPreflightReport renders the Preflight diagnostic to stderr in
// a user-friendly format. Each probed endpoint gets a line with its
// outcome and elapsed time, followed by the actionable hint.
//
// The renderer intentionally writes to stderr (not stdout) so that
// CI / scripting consumers piping argus JSON output don't get this
// mixed in with their results.
func printPreflightReport(pf azure.PreflightResult) {
	red := color.New(color.FgRed, color.Bold).FprintfFunc()
	green := color.New(color.FgGreen).FprintfFunc()
	yellow := color.New(color.FgYellow, color.Bold).FprintfFunc()
	dim := color.New(color.Faint).FprintfFunc()
	w := os.Stderr

	red(w, "\n✗ Azure connectivity check failed\n\n")
	if pf.ProxyDetected != "" {
		yellow(w, "Proxy detected: %s\n\n", pf.ProxyDetected)
	}
	fmt.Fprintln(w, "Endpoint probes:")
	for _, e := range pf.Endpoints {
		if e.OK {
			green(w, "  ✓ %-45s  %s\n", e.Name, e.Elapsed.Round(10*time.Millisecond))
		} else {
			red(w, "  ✗ %-45s  %s\n", e.Name, e.Elapsed.Round(10*time.Millisecond))
			if e.Error != "" {
				dim(w, "       error: %s\n", e.Error)
			}
		}
	}
	if pf.DiagnosticHint != "" {
		fmt.Fprintln(w)
		yellow(w, "Likely cause:\n")
		// Indent the hint so it's visually distinct from probe output.
		for _, line := range strings.Split(pf.DiagnosticHint, "\n") {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}
	fmt.Fprintln(w)
}
