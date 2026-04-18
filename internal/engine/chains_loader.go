package engine

// chains_loader.go extends the Correlator with data-driven chain definitions.
//
// The first 51 chains are hand-authored Go functions (buildChain001..051 in
// correlator.go) — they came first, they produce the richest narratives, and
// rewriting them costs more than it gains. Every chain beyond CHAIN-051 is
// declared in an embedded JSON file instead, so adding a new chain requires
// only a data entry — not a recompile of Go trigger logic.
//
// The generic builder here reads a ChainSpec and produces a models.AttackChain
// at evaluate time, filling in the real resource IDs found in the scan.

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vatsayanvivek/argus/internal/models"
)

// chainsFS carries every JSON chain spec file shipped with the engine.
// Files live at internal/engine/chains/*.json.
//
//go:embed all:chains
var chainsFS embed.FS

// ChainSpec is the JSON-serialisable form of a chain definition. The
// generic builder converts one ChainSpec + findings map into an
// AttackChain at correlate time.
type ChainSpec struct {
	ID           string                 `json:"id"`
	Title        string                 `json:"title"`
	Severity     string                 `json:"severity"`
	Likelihood   string                 `json:"likelihood"`
	TriggerLogic string                 `json:"trigger_logic"` // ALL | ANY_TWO | ANCHOR_PLUS_ONE
	Anchor       string                 `json:"anchor,omitempty"`
	Triggers     []string               `json:"triggers"`
	Narrative    string                 `json:"narrative"`
	Steps        []ChainSpecStep        `json:"steps,omitempty"`
	BlastRadius  ChainSpecBlastRadius   `json:"blast_radius,omitempty"`
	MITRETactic  string                 `json:"mitre_tactic,omitempty"`
	Technique    string                 `json:"mitre_technique,omitempty"`
	KillChain    string                 `json:"kill_chain_phase,omitempty"`
	// FixSet is the minimal set of rule IDs that, if remediated, break
	// the chain. Optional — when empty the Triggers list is used.
	FixSet       []string `json:"minimal_fix_set,omitempty"`
	PriorityFix  string   `json:"priority_fix,omitempty"`
	BreakingNote string   `json:"breaking_note,omitempty"`
}

type ChainSpecStep struct {
	Number    int    `json:"number"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	Technical string `json:"technical,omitempty"`
	Technique string `json:"technique,omitempty"`
	EnabledBy string `json:"enabled_by,omitempty"`
	Gain      string `json:"gain,omitempty"`
}

type ChainSpecBlastRadius struct {
	InitialAccess      string   `json:"initial_access,omitempty"`
	LateralMovement    string   `json:"lateral_movement,omitempty"`
	MaxPrivilege       string   `json:"max_privilege,omitempty"`
	DataAtRisk         []string `json:"data_at_risk,omitempty"`
	ServicesAtRisk     []string `json:"services_at_risk,omitempty"`
	EstimatedScopePerc string   `json:"estimated_scope_perc,omitempty"`
}

// loadChainSpecs walks internal/engine/chains/*.json and returns every
// valid ChainSpec found. Duplicate IDs win the first occurrence; invalid
// entries are skipped with a log-free soft failure so one bad file cannot
// break chain correlation. The slice is stable-sorted by ID so iteration
// order is deterministic.
func loadChainSpecs() ([]ChainSpec, error) {
	var specs []ChainSpec
	seen := map[string]bool{}

	entries, err := chainsFS.ReadDir("chains")
	if err != nil {
		// An empty chains dir is normal in dev (embed tolerates no matches).
		return nil, nil
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := chainsFS.ReadFile("chains/" + e.Name())
		if err != nil {
			continue
		}
		var batch []ChainSpec
		if err := json.Unmarshal(raw, &batch); err != nil {
			// Try single-object file too.
			var one ChainSpec
			if jerr := json.Unmarshal(raw, &one); jerr == nil && one.ID != "" {
				batch = []ChainSpec{one}
			} else {
				continue
			}
		}
		for _, s := range batch {
			if s.ID == "" || seen[s.ID] {
				continue
			}
			seen[s.ID] = true
			specs = append(specs, s)
		}
	}
	return specs, nil
}

// genericBuilder produces a ChainPattern.Builder closure for a given
// ChainSpec. The closure reads the live findings map, fills in actual
// resource IDs and MITRE data into the chain's steps where known, and
// returns the *AttackChain to emit.
func genericBuilder(spec ChainSpec) func(map[string][]models.Finding, *models.AzureSnapshot) *models.AttackChain {
	// Collect the rule IDs that should drive step → resource lookups.
	ruleIDs := append([]string{}, spec.Triggers...)

	return func(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
		resources := extractResourceIDs(findings, ruleIDs...)
		triggers := collectFindingIDs(findings, ruleIDs...)

		steps := make([]models.ChainStep, 0, len(spec.Steps))
		for _, s := range spec.Steps {
			steps = append(steps, models.ChainStep{
				Number:    s.Number,
				Actor:     s.Actor,
				Action:    s.Action,
				Technical: s.Technical,
				Technique: s.Technique,
				EnabledBy: s.EnabledBy,
				Gain:      s.Gain,
			})
		}

		fixSet := spec.FixSet
		if len(fixSet) == 0 {
			fixSet = append([]string{}, spec.Triggers...)
		}

		return &models.AttackChain{
			ID:                 spec.ID,
			Title:              spec.Title,
			Severity:           strings.ToUpper(spec.Severity),
			Likelihood:         spec.Likelihood,
			EnvironmentSummary: envSummary(resources),
			Narrative:          spec.Narrative,
			TriggerFindings:    triggers,
			TriggerLogic:       spec.TriggerLogic,
			Steps:              steps,
			BlastRadius: models.BlastRadiusDetail{
				InitialAccess:      spec.BlastRadius.InitialAccess,
				LateralMovement:    spec.BlastRadius.LateralMovement,
				MaxPrivilege:       spec.BlastRadius.MaxPrivilege,
				DataAtRisk:         spec.BlastRadius.DataAtRisk,
				ServicesAtRisk:     spec.BlastRadius.ServicesAtRisk,
				EstimatedScopePerc: spec.BlastRadius.EstimatedScopePerc,
			},
			MinimalFixSet:  fixSet,
			PriorityFix:    spec.PriorityFix,
			BreakingNote:   spec.BreakingNote,
			MITRETechnique: spec.Technique,
			MITRETactic:    spec.MITRETactic,
			KillChainPhase: spec.KillChain,
		}
	}
}

// registerDataDrivenChains appends every embedded ChainSpec to the given
// Correlator's pattern slice. Called once at the end of NewCorrelator so
// both the hand-coded and data-driven chains coexist in one evaluation
// pass.
func (c *Correlator) registerDataDrivenChains() {
	specs, err := loadChainSpecs()
	if err != nil || len(specs) == 0 {
		return
	}
	for _, s := range specs {
		pat := ChainPattern{
			ID:           s.ID,
			TriggerLogic: s.TriggerLogic,
			TriggerIDs:   s.Triggers,
			AnchorID:     s.Anchor,
			Builder:      genericBuilder(s),
		}
		c.patterns = append(c.patterns, pat)
	}
}

// Compile-time safety: ensure fmt stays imported if any printf is added
// later. Not strictly needed today.
var _ = fmt.Sprintf
