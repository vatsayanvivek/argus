package reporter

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vatsayanvivek/argus/internal/models"
)

// EvidenceGenerator builds a zipped auditor evidence bundle.
type EvidenceGenerator struct{}

// NewEvidenceGenerator creates a new evidence bundle generator.
func NewEvidenceGenerator() *EvidenceGenerator { return &EvidenceGenerator{} }

// Generate writes the zip bundle to outputDir and returns its absolute path.
// The zip internally prefixes every file with "argus-evidence-<timestamp>/".
func (g *EvidenceGenerator) Generate(
	snapshot *models.AzureSnapshot,
	findings []models.Finding,
	chains []models.AttackChain,
	score *models.ZTScoreReport,
	driftFindings []models.DriftFinding,
	outputDir, timestamp string,
) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", fmt.Errorf("evidence: mkdir %s: %w", outputDir, err)
	}

	bundleName := fmt.Sprintf("argus-evidence-%s", timestamp)
	zipName := bundleName + ".zip"
	zipPath := filepath.Join(outputDir, zipName)
	absZipPath, err := filepath.Abs(zipPath)
	if err != nil {
		absZipPath = zipPath
	}

	type entry struct {
		name string
		data []byte
	}
	var entries []entry

	// 1. executive_summary.json
	execSummary, err := buildExecutiveSummary(snapshot, findings, chains, score, driftFindings)
	if err != nil {
		return "", fmt.Errorf("evidence: executive summary: %w", err)
	}
	entries = append(entries, entry{"executive_summary.json", execSummary})

	// 2. zt_score_report.json
	ztData, err := jsonBytes(score)
	if err != nil {
		return "", fmt.Errorf("evidence: zt score: %w", err)
	}
	entries = append(entries, entry{"zt_score_report.json", ztData})

	// 3. attack_chains.json
	chainsData, err := jsonBytes(chains)
	if err != nil {
		return "", fmt.Errorf("evidence: chains: %w", err)
	}
	entries = append(entries, entry{"attack_chains.json", chainsData})

	// 4. cis_azure_compliance.csv
	cisCSV, err := buildCISAzureCSV(findings)
	if err != nil {
		return "", fmt.Errorf("evidence: cis csv: %w", err)
	}
	entries = append(entries, entry{"cis_azure_compliance.csv", cisCSV})

	// 5. nist_800_53_mapping.csv
	nist53CSV, err := buildNIST80053CSV(findings)
	if err != nil {
		return "", fmt.Errorf("evidence: nist 800-53 csv: %w", err)
	}
	entries = append(entries, entry{"nist_800_53_mapping.csv", nist53CSV})

	// 6. nist_800_207_assessment.csv
	nist207CSV, err := buildNIST800207CSV(findings, chains, score)
	if err != nil {
		return "", fmt.Errorf("evidence: nist 800-207 csv: %w", err)
	}
	entries = append(entries, entry{"nist_800_207_assessment.csv", nist207CSV})

	// 7. remediation_plan.md
	remediationMD := buildRemediationPlan(findings, chains)
	entries = append(entries, entry{"remediation_plan.md", remediationMD})

	// 8. drift_report.csv (conditional)
	if len(driftFindings) > 0 {
		driftCSV, err := buildDriftCSV(driftFindings)
		if err != nil {
			return "", fmt.Errorf("evidence: drift csv: %w", err)
		}
		entries = append(entries, entry{"drift_report.csv", driftCSV})
	}

	// 9. raw_findings.json
	rawData, err := jsonBytes(findings)
	if err != nil {
		return "", fmt.Errorf("evidence: raw findings: %w", err)
	}
	entries = append(entries, entry{"raw_findings.json", rawData})

	// Write zip
	f, err := os.Create(zipPath)
	if err != nil {
		return "", fmt.Errorf("evidence: create zip: %w", err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for _, e := range entries {
		internalPath := bundleName + "/" + e.name
		w, err := zw.Create(internalPath)
		if err != nil {
			_ = zw.Close()
			return "", fmt.Errorf("evidence: zip create %s: %w", internalPath, err)
		}
		if _, err := w.Write(e.data); err != nil {
			_ = zw.Close()
			return "", fmt.Errorf("evidence: zip write %s: %w", internalPath, err)
		}
	}
	if err := zw.Close(); err != nil {
		return "", fmt.Errorf("evidence: zip close: %w", err)
	}

	return absZipPath, nil
}

// ---------- JSON helpers ----------

func jsonBytes(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// ---------- Executive summary ----------

func buildExecutiveSummary(
	snapshot *models.AzureSnapshot,
	findings []models.Finding,
	chains []models.AttackChain,
	score *models.ZTScoreReport,
	driftFindings []models.DriftFinding,
) ([]byte, error) {
	sevCounts := map[string]int{}
	for _, f := range findings {
		sevCounts[strings.ToUpper(f.Severity)]++
	}

	topChains := make([]map[string]any, 0, len(chains))
	for _, c := range chains {
		if len(topChains) >= 5 {
			break
		}
		topChains = append(topChains, map[string]any{
			"id":       c.ID,
			"title":    c.Title,
			"severity": c.Severity,
		})
	}

	out := map[string]any{
		"tool":           "ARGUS",
		"version":        "1.0.0",
		"findings_total": len(findings),
		"findings_by_severity": sevCounts,
		"chains_detected": len(chains),
		"top_chains":      topChains,
		"drift_findings":  len(driftFindings),
	}
	if snapshot != nil {
		out["subscription_id"] = snapshot.SubscriptionID
		out["subscription_name"] = snapshot.SubscriptionName
		out["tenant_id"] = snapshot.TenantID
		out["scan_time"] = snapshot.ScanTime
		out["collection_mode"] = snapshot.CollectionMode
	}
	if score != nil {
		out["overall_score"] = score.OverallScore
		out["grade"] = score.Grade
		out["maturity_level"] = score.MaturityLevel
	}
	return jsonBytes(out)
}

// ---------- CSV builders ----------

func buildCISAzureCSV(findings []models.Finding) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write([]string{"CIS_Rule", "Level", "Title", "Status", "Resource", "Finding_ID", "Severity", "Remediation"}); err != nil {
		return nil, err
	}

	rows := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		if f.CISRule == "" {
			continue
		}
		rows = append(rows, f)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].CISRule != rows[j].CISRule {
			return rows[i].CISRule < rows[j].CISRule
		}
		return rows[i].ID < rows[j].ID
	})

	for _, f := range rows {
		row := []string{
			f.CISRule,
			f.CISLevel,
			f.Title,
			"FAIL",
			f.ResourceName,
			f.ID,
			f.Severity,
			oneLine(f.RemediationText),
		}
		if err := w.Write(row); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func buildNIST80053CSV(findings []models.Finding) ([]byte, error) {
	type agg struct {
		Control   string
		FindingIDs []string
		Resources  []string
		HighestSev string
	}
	byControl := map[string]*agg{}
	for _, f := range findings {
		ctrl := f.NIST80053Control
		if ctrl == "" {
			continue
		}
		a, ok := byControl[ctrl]
		if !ok {
			a = &agg{Control: ctrl, HighestSev: f.Severity}
			byControl[ctrl] = a
		}
		a.FindingIDs = append(a.FindingIDs, f.ID)
		a.Resources = append(a.Resources, f.ResourceName)
		if severityRank(f.Severity) < severityRank(a.HighestSev) {
			a.HighestSev = f.Severity
		}
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write([]string{"Control_ID", "Control_Name", "Status", "Finding_IDs", "Resources", "Highest_Severity"}); err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(byControl))
	for k := range byControl {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a := byControl[k]
		row := []string{
			a.Control,
			nist80053Name(a.Control),
			"NON_COMPLIANT",
			strings.Join(dedup(a.FindingIDs), "; "),
			strings.Join(dedup(a.Resources), "; "),
			a.HighestSev,
		}
		if err := w.Write(row); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func buildNIST800207CSV(findings []models.Finding, chains []models.AttackChain, score *models.ZTScoreReport) ([]byte, error) {
	type agg struct {
		Tenet          string
		Description    string
		Status         string
		ViolationCount int
		HighestSev     string
		ChainCount     int
	}

	byTenet := map[string]*agg{}

	// Seed from score pillars if we have them
	if score != nil {
		for pillar, p := range score.PillarScores {
			key := p.NISTTenet
			if key == "" {
				key = pillar
			}
			byTenet[key] = &agg{
				Tenet:       key,
				Description: nist800207Description(key),
				Status:      p.TenetStatus,
				ChainCount:  p.ChainCount,
			}
		}
	}

	for _, f := range findings {
		key := f.NIST800207Tenet
		if key == "" {
			continue
		}
		a, ok := byTenet[key]
		if !ok {
			a = &agg{Tenet: key, Description: nist800207Description(key), Status: "AT_RISK", HighestSev: f.Severity}
			byTenet[key] = a
		}
		a.ViolationCount++
		if a.HighestSev == "" || severityRank(f.Severity) < severityRank(a.HighestSev) {
			a.HighestSev = f.Severity
		}
	}

	// Fallback chain counts if no score provided
	if score == nil {
		for _, c := range chains {
			for _, tf := range c.TriggerFindings {
				for _, f := range findings {
					if f.ID == tf && f.NIST800207Tenet != "" {
						if a, ok := byTenet[f.NIST800207Tenet]; ok {
							a.ChainCount++
						}
						break
					}
				}
			}
		}
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write([]string{"Tenet", "Description", "Status", "Violation_Count", "Highest_Severity", "Chain_Count"}); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(byTenet))
	for k := range byTenet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a := byTenet[k]
		status := a.Status
		if status == "" {
			if a.ViolationCount == 0 {
				status = "SATISFIED"
			} else {
				status = "AT_RISK"
			}
		}
		sev := a.HighestSev
		if sev == "" {
			sev = "NONE"
		}
		row := []string{
			a.Tenet,
			a.Description,
			status,
			fmt.Sprintf("%d", a.ViolationCount),
			sev,
			fmt.Sprintf("%d", a.ChainCount),
		}
		if err := w.Write(row); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func buildDriftCSV(drift []models.DriftFinding) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write([]string{"Identity_Name", "Identity_ARN", "Type", "Granted_Actions", "Used_Actions", "Unused_Actions", "Unused_Percentage", "Blast_Radius", "Last_Activity", "Recommendation"}); err != nil {
		return nil, err
	}
	for _, d := range drift {
		row := []string{
			d.IdentityName,
			d.IdentityARN,
			d.IdentityType,
			fmt.Sprintf("%d", len(d.GrantedActions)),
			fmt.Sprintf("%d", len(d.UsedActions)),
			fmt.Sprintf("%d", len(d.UnusedActions)),
			fmt.Sprintf("%.1f", d.UnusedPercentage),
			d.BlastRadius,
			d.LastActivity,
			oneLine(d.Recommendation),
		}
		if err := w.Write(row); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---------- Remediation plan markdown ----------

func buildRemediationPlan(findings []models.Finding, chains []models.AttackChain) []byte {
	var b bytes.Buffer
	b.WriteString("# ARGUS Remediation Plan\n\n")
	b.WriteString("This plan is ordered to deliver maximum risk reduction per unit of effort: ")
	b.WriteString("chain-breaking remediations first, then by severity.\n\n")

	// Sort: chain-breaking first, then severity
	sorted := make([]models.Finding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		iCB := sorted[i].ChainPriority || len(sorted[i].ParticipatesInChains) > 0
		jCB := sorted[j].ChainPriority || len(sorted[j].ParticipatesInChains) > 0
		if iCB != jCB {
			return iCB
		}
		return severityRank(sorted[i].Severity) < severityRank(sorted[j].Severity)
	})

	// Chain-breaking section
	b.WriteString("## Phase 1 — Break the Attack Chains\n\n")
	if len(chains) == 0 {
		b.WriteString("_No attack chains detected._\n\n")
	} else {
		for _, c := range chains {
			fmt.Fprintf(&b, "### %s — %s (%s)\n\n", c.ID, c.Title, c.Severity)
			if c.BreakingNote != "" {
				fmt.Fprintf(&b, "%s\n\n", c.BreakingNote)
			}
			if c.PriorityFix != "" {
				fmt.Fprintf(&b, "**Priority fix:** `%s`\n\n", c.PriorityFix)
			}
			if len(c.MinimalFixSet) > 0 {
				b.WriteString("**Minimal fix set:**\n\n")
				for _, r := range c.MinimalFixSet {
					fmt.Fprintf(&b, "- `%s`\n", r)
				}
				b.WriteString("\n")
			}
		}
	}

	// Per-finding section
	b.WriteString("## Phase 2 — Per-Finding Remediation\n\n")
	for _, f := range sorted {
		marker := ""
		if f.ChainPriority || len(f.ParticipatesInChains) > 0 {
			marker = " — CHAIN-BREAKING"
		}
		fmt.Fprintf(&b, "### %s — %s [%s]%s\n\n", f.ID, f.Title, f.Severity, marker)
		if f.ResourceName != "" {
			fmt.Fprintf(&b, "**Resource:** `%s` (%s)\n\n", f.ResourceName, f.ResourceType)
		}
		if f.Pillar != "" {
			fmt.Fprintf(&b, "**Pillar:** %s\n\n", f.Pillar)
		}
		if f.EstimatedEffortHours > 0 {
			fmt.Fprintf(&b, "**Estimated effort:** %d hour(s)\n\n", f.EstimatedEffortHours)
		}
		if f.Description != "" {
			fmt.Fprintf(&b, "%s\n\n", f.Description)
		}
		if f.RemediationText != "" {
			fmt.Fprintf(&b, "**Remediation:** %s\n\n", f.RemediationText)
		}
		if f.RemediationTerraform != "" {
			b.WriteString("**Terraform:**\n\n```hcl\n")
			b.WriteString(f.RemediationTerraform)
			b.WriteString("\n```\n\n")
		}
		if f.RemediationCLI != "" {
			b.WriteString("**Azure CLI:**\n\n```bash\n")
			b.WriteString(f.RemediationCLI)
			b.WriteString("\n```\n\n")
		}
		b.WriteString("---\n\n")
	}

	return b.Bytes()
}

// ---------- Misc helpers ----------

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func nist80053Name(id string) string {
	names := map[string]string{
		"AC-2":  "Account Management",
		"AC-3":  "Access Enforcement",
		"AC-6":  "Least Privilege",
		"AU-2":  "Audit Events",
		"AU-12": "Audit Generation",
		"CM-2":  "Baseline Configuration",
		"CM-6":  "Configuration Settings",
		"IA-2":  "Identification and Authentication",
		"IA-5":  "Authenticator Management",
		"SC-7":  "Boundary Protection",
		"SC-8":  "Transmission Confidentiality and Integrity",
		"SC-13": "Cryptographic Protection",
		"SC-28": "Protection of Information at Rest",
		"SI-4":  "System Monitoring",
	}
	if n, ok := names[id]; ok {
		return n
	}
	return "Control " + id
}

func nist800207Description(tenet string) string {
	descs := map[string]string{
		"1": "All data sources and computing services are considered resources.",
		"2": "All communication is secured regardless of network location.",
		"3": "Access to individual enterprise resources is granted on a per-session basis.",
		"4": "Access to resources is determined by dynamic policy.",
		"5": "The enterprise monitors and measures the integrity and security posture of all owned and associated assets.",
		"6": "All resource authentication and authorization are dynamic and strictly enforced before access is allowed.",
		"7": "The enterprise collects as much information as possible about the current state of assets, network infrastructure and communications and uses it to improve its security posture.",
	}
	if d, ok := descs[tenet]; ok {
		return d
	}
	// allow "Tenet 3" style keys
	for k, v := range descs {
		if strings.Contains(tenet, k) {
			return v
		}
	}
	return tenet
}
