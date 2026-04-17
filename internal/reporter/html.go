package reporter

import (
	"embed"
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/vatsayanvivek/argus/internal/models"
	"github.com/vatsayanvivek/argus/internal/trend"
)

//go:embed templates/report.html
var templateFS embed.FS

// ReportContext is the view model passed to the HTML template.
type ReportContext struct {
	Tool                    string
	Version                 string
	GeneratedAt             string
	SubscriptionID          string
	SubscriptionName        string
	TenantID                string
	ScanTime                string
	CollectionMode          string
	Score                   *models.ZTScoreReport
	Findings                []models.Finding
	Chains                  []models.AttackChain
	DriftFindings           []models.DriftFinding
	Narrative               string
	TrendReport             *trend.TrendReport
	// Graph permissions warning — surfaced when the scanning identity
	// did not have full Microsoft Graph access. The template renders a
	// prominent yellow banner so the user does not get a false sense
	// of security from a partial scan.
	GraphPermissionsLimited bool
	GraphPermissionsMissing []string
	// QuickWins is the Pareto remediation roadmap — top N rules whose
	// fix breaks the most attack chains for the least effort.
	QuickWins []models.QuickWinItem
	// UniqueResourcesByRule maps a rule ID to the number of distinct
	// resources it fired against. The template uses this to render
	// "this rule fired against N resources" alongside the rule title
	// in the findings table.
	UniqueResourcesByRule map[string]int
}

// HTMLReporter produces the primary consulting-deliverable HTML report.
type HTMLReporter struct {
	tmpl                    *template.Template
	trendReport             *trend.TrendReport
	quickWins               []models.QuickWinItem
	graphPermissionsLimited bool
	graphPermissionsMissing []string
	version                 string
}

// SetVersion records the build-time version of argus so the footer of
// the HTML report shows the actual version that generated it, not a
// hard-coded placeholder.
func (r *HTMLReporter) SetVersion(v string) {
	if v != "" {
		r.version = v
	}
}

// SetTrendReport attaches a trend report to the reporter so it can be
// threaded into the ReportContext on the next Generate call. Passing
// nil clears any previously attached report.
func (r *HTMLReporter) SetTrendReport(tr *trend.TrendReport) {
	r.trendReport = tr
}

// SetQuickWins attaches the Pareto remediation roadmap so the template
// can render the "Top 5 Quick Wins" section. Passing nil clears it.
func (r *HTMLReporter) SetQuickWins(items []models.QuickWinItem) {
	r.quickWins = items
}

// SetGraphPermissionsWarning records that the scanning identity did
// not have full Microsoft Graph access. When set, the report renders
// a prominent banner listing the missing scopes.
func (r *HTMLReporter) SetGraphPermissionsWarning(limited bool, missing []string) {
	r.graphPermissionsLimited = limited
	r.graphPermissionsMissing = missing
}

// NewHTMLReporter parses the embedded template file once.
func NewHTMLReporter() *HTMLReporter {
	funcMap := buildFuncMap()
	data, err := templateFS.ReadFile("templates/report.html")
	if err != nil {
		return &HTMLReporter{tmpl: nil, version: "dev"}
	}
	tmpl, err := template.New("report.html").Funcs(funcMap).Parse(string(data))
	if err != nil {
		return &HTMLReporter{tmpl: nil, version: "dev"}
	}
	return &HTMLReporter{tmpl: tmpl, version: "dev"}
}

// buildFuncMap returns the template func map shared by all template parses.
func buildFuncMap() template.FuncMap {
	return template.FuncMap{
		"add": func(a, b float64) float64 { return a + b },
		"sub": func(a, b float64) float64 { return a - b },
		"subi": func(a, b int) int { return a - b },
		"mul": func(a, b float64) float64 { return a * b },
		"div": func(a, b float64) float64 {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		// substituteResource replaces generic placeholders in a remediation
		// snippet with the actual finding's resource name and resource group.
		// This makes Terraform/CLI snippets immediately runnable for the
		// specific resource that triggered the finding.
		"substituteResource": func(snippet string, f models.Finding) string {
			out := snippet
			rname := f.ResourceName
			rg := f.ResourceGroup
			if rname == "" {
				rname = "<resource-name>"
			}
			if rg == "" {
				rg = "<resource-group>"
			}
			replacements := map[string]string{
				"<name>":             rname,
				"<resource-name>":    rname,
				"<resource_name>":    rname,
				"<vm-name>":          rname,
				"<storage-name>":     rname,
				"<sa>":               rname,
				"<vm>":               rname,
				"<kv>":               rname,
				"<keyvault>":         rname,
				"<sql-server>":       rname,
				"<server>":           rname,
				"<cluster>":          rname,
				"<aks>":              rname,
				"<app>":              rname,
				"<app-name>":         rname,
				"<webapp>":           rname,
				"<function-name>":    rname,
				"<nsg>":              rname,
				"<rg>":               rg,
				"<resource-group>":   rg,
				"<resource_group>":   rg,
			}
			for placeholder, value := range replacements {
				out = strings.ReplaceAll(out, placeholder, value)
			}
			return out
		},
	}
}

// Generate builds the ReportContext and renders the HTML report to outputPath.
func (r *HTMLReporter) Generate(
	snapshot *models.AzureSnapshot,
	findings []models.Finding,
	chains []models.AttackChain,
	score *models.ZTScoreReport,
	driftFindings []models.DriftFinding,
	outputPath string,
) error {
	if r.tmpl == nil {
		return fmt.Errorf("html reporter: embedded template not loaded")
	}

	sortedFindings := sortFindingsForReport(findings)
	sortedChains := sortChainsForReport(chains)

	// Build rule_id → unique resource count map for the template. After
	// the engine's CollapseDuplicates pass, a single finding may carry
	// its own ResourceID plus a list of AffectedResources — count both
	// so the "rule fires on N resources" label in the HTML shows the
	// true number of affected resources, not a post-collapse underhang.
	uniqueByRule := map[string]map[string]bool{}
	for _, f := range findings {
		if uniqueByRule[f.ID] == nil {
			uniqueByRule[f.ID] = map[string]bool{}
		}
		if f.ResourceID != "" {
			uniqueByRule[f.ID][f.ResourceID] = true
		}
		for _, r := range f.AffectedResources {
			if r != "" {
				uniqueByRule[f.ID][r] = true
			}
		}
	}
	uniqueResourcesByRule := make(map[string]int, len(uniqueByRule))
	for rule, set := range uniqueByRule {
		uniqueResourcesByRule[rule] = len(set)
	}

	ctx := ReportContext{
		Tool:                    "ARGUS",
		Version:                 r.version,
		GeneratedAt:             time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Findings:                sortedFindings,
		Chains:                  sortedChains,
		Score:                   score,
		DriftFindings:           driftFindings,
		Narrative:               buildNarrative(snapshot, sortedFindings, sortedChains, score),
		TrendReport:             r.trendReport,
		QuickWins:               r.quickWins,
		GraphPermissionsLimited: r.graphPermissionsLimited,
		GraphPermissionsMissing: r.graphPermissionsMissing,
		UniqueResourcesByRule:   uniqueResourcesByRule,
	}

	if snapshot != nil {
		ctx.SubscriptionID = snapshot.SubscriptionID
		ctx.SubscriptionName = snapshot.SubscriptionName
		ctx.TenantID = snapshot.TenantID
		ctx.ScanTime = snapshot.ScanTime.UTC().Format("2006-01-02 15:04:05 UTC")
		ctx.CollectionMode = snapshot.CollectionMode
		// If the caller didn't explicitly set the Graph perms warning,
		// pull it from the snapshot. This preserves backward compat
		// for callers (like score and drift commands) that don't
		// invoke SetGraphPermissionsWarning explicitly.
		if !ctx.GraphPermissionsLimited && snapshot.GraphPermissionsLimited {
			ctx.GraphPermissionsLimited = true
			ctx.GraphPermissionsMissing = snapshot.GraphPermissionsMissing
		}
	}
	if ctx.SubscriptionName == "" {
		ctx.SubscriptionName = "Azure Subscription"
	}
	if ctx.CollectionMode == "" {
		ctx.CollectionMode = "unknown"
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("html reporter: create %s: %w", outputPath, err)
	}
	defer f.Close()

	if err := r.tmpl.Execute(f, ctx); err != nil {
		return fmt.Errorf("html reporter: execute template: %w", err)
	}
	return nil
}

// severityRank orders severities from most to least severe.
func severityRank(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	default:
		return 4
	}
}

// sortFindingsForReport puts chain-participating findings first, then orders by severity.
func sortFindingsForReport(in []models.Finding) []models.Finding {
	out := make([]models.Finding, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		iChain := len(out[i].ParticipatesInChains) > 0
		jChain := len(out[j].ParticipatesInChains) > 0
		if iChain != jChain {
			return iChain
		}
		if out[i].ChainPriority != out[j].ChainPriority {
			return out[i].ChainPriority
		}
		ri, rj := severityRank(out[i].Severity), severityRank(out[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// sortChainsForReport orders chains by severity, then title.
func sortChainsForReport(in []models.AttackChain) []models.AttackChain {
	out := make([]models.AttackChain, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := severityRank(out[i].Severity), severityRank(out[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return out[i].Title < out[j].Title
	})
	return out
}

// buildNarrative creates the one-paragraph executive narrative.
func buildNarrative(
	snapshot *models.AzureSnapshot,
	findings []models.Finding,
	chains []models.AttackChain,
	score *models.ZTScoreReport,
) string {
	subName := "the subscription"
	if snapshot != nil && snapshot.SubscriptionName != "" {
		subName = snapshot.SubscriptionName
	}

	var b strings.Builder

	if score != nil {
		fmt.Fprintf(&b,
			"Subscription %s received a Zero Trust score of %.1f/100 (Grade %s, Maturity: %s). ",
			subName, score.OverallScore, score.Grade, score.MaturityLevel,
		)
	} else {
		fmt.Fprintf(&b, "Subscription %s was assessed by ARGUS. ", subName)
	}

	if len(chains) > 0 {
		topTitle := chains[0].Title
		topSev := chains[0].Severity
		fmt.Fprintf(&b,
			"%d attack chain%s %s identified — the most critical being \"%s\" (%s). ",
			len(chains),
			plural(len(chains)),
			wereOrWas(len(chains)),
			topTitle,
			topSev,
		)
	} else {
		b.WriteString("No end-to-end attack chains were correlated from the current findings. ")
	}

	lowestPillar := ""
	if score != nil && len(score.PillarScores) > 0 {
		var lowScore float64 = 1e9
		for name, p := range score.PillarScores {
			if p.Score < lowScore {
				lowScore = p.Score
				lowestPillar = name
			}
		}
	}

	criticalInPillar := 0
	totalCritical := 0
	for _, f := range findings {
		if strings.EqualFold(f.Severity, "CRITICAL") {
			totalCritical++
			if lowestPillar != "" && strings.EqualFold(f.Pillar, lowestPillar) {
				criticalInPillar++
			}
		}
	}

	chainsBroken := 0
	if lowestPillar != "" {
		targetRules := map[string]bool{}
		for _, f := range findings {
			if strings.EqualFold(f.Severity, "CRITICAL") && strings.EqualFold(f.Pillar, lowestPillar) {
				targetRules[f.ID] = true
			}
		}
		for _, c := range chains {
			for _, t := range c.TriggerFindings {
				if targetRules[t] {
					chainsBroken++
					break
				}
			}
		}
	}

	if lowestPillar != "" && criticalInPillar > 0 {
		fmt.Fprintf(&b,
			"Addressing the %d CRITICAL finding%s in the %s pillar would break %d of the %d detected chain%s. ",
			criticalInPillar, plural(criticalInPillar), lowestPillar,
			chainsBroken, len(chains), plural(len(chains)),
		)
	} else if totalCritical > 0 {
		fmt.Fprintf(&b,
			"%d CRITICAL finding%s across the environment should be remediated first. ",
			totalCritical, plural(totalCritical),
		)
	}

	topCriticals := topNCritical(findings, 3)
	if len(topCriticals) > 0 {
		titles := make([]string, 0, len(topCriticals))
		for _, f := range topCriticals {
			titles = append(titles, fmt.Sprintf("\"%s\"", f.Title))
		}
		fmt.Fprintf(&b, "Highest-impact individual issues: %s.", strings.Join(titles, "; "))
	}

	return strings.TrimSpace(b.String())
}

func topNCritical(findings []models.Finding, n int) []models.Finding {
	var out []models.Finding
	for _, f := range findings {
		if strings.EqualFold(f.Severity, "CRITICAL") {
			out = append(out, f)
			if len(out) == n {
				break
			}
		}
	}
	return out
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func wereOrWas(n int) string {
	if n == 1 {
		return "was"
	}
	return "were"
}
