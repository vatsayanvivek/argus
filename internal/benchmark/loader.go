package benchmark

import (
	"embed"
	"encoding/csv"
	"fmt"
	"io"
	"io/fs"
	"strconv"
	"strings"
)

// dataFS embeds the benchmark CSV tree. As with internal/engine/policies,
// Go's //go:embed directive does not allow parent-path elements, so the
// project's Makefile copies argus/data/** into internal/benchmark/data/**
// before `go build`. The directory always ships with at least a .keep
// sentinel file so the embed directive is satisfied even when CSVs are
// not yet present.
//
//go:embed all:data
var dataFS embed.FS

// CISRule captures one row of the CIS Microsoft Azure Foundations
// benchmark. The CSV columns are expected in the order declared below.
type CISRule struct {
	RuleID          string
	Section         string
	Title           string
	Description     string
	Rationale       string
	Impact          string
	Level           string
	CISControl      string
	NIST80053       string
	NIST800207Tenet string
	AuditProcedure  string
	Remediation     string
	RegoFile        string
}

// ZTTenet is one NIST SP 800-207 zero-trust tenet with Azure context.
type ZTTenet struct {
	TenetID        string
	TenetNumber    string
	Title          string
	Description    string
	AzureRelevance string
	PillarMapping  string
}

// NISTControl is one NIST SP 800-53 rev5 control entry.
type NISTControl struct {
	ControlID   string
	Family      string
	Title       string
	Description string
}

// MITRETechnique is one ATT&CK technique relevant to Azure environments.
type MITRETechnique struct {
	TechniqueID    string
	Tactic         string
	Name           string
	Description    string
	AzureRelevance string
	Detection      string
}

// RemediationDetail is the human-authored remediation guidance for a
// specific ARGUS rule. Multiple fields may be blank for rules that only
// have portal or CLI guidance, etc.
type RemediationDetail struct {
	RuleID          string
	RemediationText string
	Terraform       string
	AzureCLI        string
	PortalSteps     string
	EffortHours     int
	RiskIfNotFixed  string
}

// BenchmarkLoader holds every benchmark table parsed from the embedded CSV
// tree, keyed for O(1) lookup during finding enrichment.
type BenchmarkLoader struct {
	CISRules     map[string]CISRule
	ZTTenets     map[string]ZTTenet
	NISTControls map[string]NISTControl
	Crosswalk    map[string][]string // cis_rule_id -> []nist_controls
	MITREMap     map[string]MITRETechnique
	Remediation  map[string]RemediationDetail
}

// NewBenchmarkLoader reads the six CSV tables embedded under data/ and
// returns a fully populated loader. Missing files are tolerated (the
// corresponding map is simply empty) so that partial data sets still boot.
func NewBenchmarkLoader() (*BenchmarkLoader, error) {
	l := &BenchmarkLoader{
		CISRules:     make(map[string]CISRule),
		ZTTenets:     make(map[string]ZTTenet),
		NISTControls: make(map[string]NISTControl),
		Crosswalk:    make(map[string][]string),
		MITREMap:     make(map[string]MITRETechnique),
		Remediation:  make(map[string]RemediationDetail),
	}

	if err := l.loadCISRules("data/benchmarks/cis_azure_2.0.csv"); err != nil {
		return nil, fmt.Errorf("cis rules: %w", err)
	}
	if err := l.loadZTTenets("data/benchmarks/nist_800_207_tenets.csv"); err != nil {
		return nil, fmt.Errorf("zt tenets: %w", err)
	}
	if err := l.loadCrosswalk("data/benchmarks/cis_nist_crosswalk.csv"); err != nil {
		return nil, fmt.Errorf("crosswalk: %w", err)
	}
	if err := l.loadMITRE("data/benchmarks/mitre_attack_cloud.csv"); err != nil {
		return nil, fmt.Errorf("mitre: %w", err)
	}
	if err := l.loadNIST80053("data/benchmarks/nist_800_53_rev5.csv"); err != nil {
		return nil, fmt.Errorf("nist 800-53: %w", err)
	}
	if err := l.loadRemediation("data/remediation/azure_remediation.csv"); err != nil {
		return nil, fmt.Errorf("remediation: %w", err)
	}

	return l, nil
}

// BenchmarksFS exposes the embedded data tree for tooling and tests.
func BenchmarksFS() fs.FS {
	return dataFS
}

// readCSV opens a file from the embedded FS and returns every data row
// (header excluded). If the file does not exist the function returns an
// empty slice with no error so the caller can tolerate partial datasets.
func readCSV(path string) ([][]string, error) {
	f, err := dataFS.Open(path)
	if err != nil {
		// Treat missing files as empty rather than fatal.
		return nil, nil
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1 // allow variable field counts per row
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true

	rows := make([][]string, 0, 64)
	first := true
	for {
		rec, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if first {
			first = false
			continue
		}
		rows = append(rows, rec)
	}
	return rows, nil
}

// field safely reads column i from a record, returning "" if out of range.
func field(rec []string, i int) string {
	if i < 0 || i >= len(rec) {
		return ""
	}
	return strings.TrimSpace(rec[i])
}

func (l *BenchmarkLoader) loadCISRules(path string) error {
	rows, err := readCSV(path)
	if err != nil {
		return err
	}
	for _, r := range rows {
		rule := CISRule{
			RuleID:          field(r, 0),
			Section:         field(r, 1),
			Title:           field(r, 2),
			Description:     field(r, 3),
			Rationale:       field(r, 4),
			Impact:          field(r, 5),
			Level:           field(r, 6),
			CISControl:      field(r, 7),
			NIST80053:       field(r, 8),
			NIST800207Tenet: field(r, 9),
			AuditProcedure:  field(r, 10),
			Remediation:     field(r, 11),
			RegoFile:        field(r, 12),
		}
		if rule.RuleID == "" {
			continue
		}
		l.CISRules[rule.RuleID] = rule
	}
	return nil
}

func (l *BenchmarkLoader) loadZTTenets(path string) error {
	rows, err := readCSV(path)
	if err != nil {
		return err
	}
	for _, r := range rows {
		t := ZTTenet{
			TenetID:        field(r, 0),
			TenetNumber:    field(r, 1),
			Title:          field(r, 2),
			Description:    field(r, 3),
			AzureRelevance: field(r, 4),
			PillarMapping:  field(r, 5),
		}
		if t.TenetID == "" {
			continue
		}
		l.ZTTenets[t.TenetID] = t
	}
	return nil
}

func (l *BenchmarkLoader) loadCrosswalk(path string) error {
	rows, err := readCSV(path)
	if err != nil {
		return err
	}
	// Expected columns: cis_rule_id, nist_800_53_controls (semicolon or
	// comma separated list).
	for _, r := range rows {
		cis := field(r, 0)
		if cis == "" {
			continue
		}
		raw := field(r, 1)
		if raw == "" {
			l.Crosswalk[cis] = []string{}
			continue
		}
		var parts []string
		for _, sep := range []string{";", ","} {
			if strings.Contains(raw, sep) {
				parts = strings.Split(raw, sep)
				break
			}
		}
		if parts == nil {
			parts = []string{raw}
		}
		clean := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				clean = append(clean, p)
			}
		}
		l.Crosswalk[cis] = clean
	}
	return nil
}

func (l *BenchmarkLoader) loadMITRE(path string) error {
	rows, err := readCSV(path)
	if err != nil {
		return err
	}
	for _, r := range rows {
		t := MITRETechnique{
			TechniqueID:    field(r, 0),
			Tactic:         field(r, 1),
			Name:           field(r, 2),
			Description:    field(r, 3),
			AzureRelevance: field(r, 4),
			Detection:      field(r, 5),
		}
		if t.TechniqueID == "" {
			continue
		}
		l.MITREMap[t.TechniqueID] = t
	}
	return nil
}

func (l *BenchmarkLoader) loadNIST80053(path string) error {
	rows, err := readCSV(path)
	if err != nil {
		return err
	}
	for _, r := range rows {
		c := NISTControl{
			ControlID:   field(r, 0),
			Family:      field(r, 1),
			Title:       field(r, 2),
			Description: field(r, 3),
		}
		if c.ControlID == "" {
			continue
		}
		l.NISTControls[c.ControlID] = c
	}
	return nil
}

func (l *BenchmarkLoader) loadRemediation(path string) error {
	rows, err := readCSV(path)
	if err != nil {
		return err
	}
	for _, r := range rows {
		effort := 0
		if e := field(r, 5); e != "" {
			if v, err := strconv.Atoi(e); err == nil {
				effort = v
			}
		}
		d := RemediationDetail{
			RuleID:          field(r, 0),
			RemediationText: field(r, 1),
			Terraform:       field(r, 2),
			AzureCLI:        field(r, 3),
			PortalSteps:     field(r, 4),
			EffortHours:     effort,
			RiskIfNotFixed:  field(r, 6),
		}
		if d.RuleID == "" {
			continue
		}
		l.Remediation[d.RuleID] = d
	}
	return nil
}
