package models

// AttackChain is the PRIMARY OUTPUT MODEL of ARGUS.
// Individual findings are inputs; chains are the product.
type AttackChain struct {
	ID                 string                `json:"id"`
	Title              string                `json:"title"`
	Severity           string                `json:"severity"`
	Likelihood         string                `json:"likelihood"`
	// Confidence is how sure ARGUS is that the chain is actually
	// exploitable given the data it saw. For hand-authored CHAIN-*
	// patterns the confidence is always "High" because the trigger
	// rules embed the evidence. For graph-discovered DISC-* chains
	// the confidence reflects path length, role-edge strength, and
	// whether identity collection was limited.
	//   "High"   — direct, short path with a privilege-granting role
	//   "Medium" — multi-hop with known privilege-granting roles
	//   "Low"    — long path, weak roles, or partial data collection
	Confidence         string                `json:"confidence,omitempty"`
	EnvironmentSummary string                `json:"environment_summary"`
	Narrative          string                `json:"narrative"`
	TriggerFindings    []string              `json:"trigger_findings"`
	TriggerLogic       string                `json:"trigger_logic"` // ALL | ANY_TWO | ANCHOR_PLUS_ONE
	Steps              []ChainStep           `json:"steps"`
	BlastRadius        BlastRadiusDetail     `json:"blast_radius"`
	RegulatoryImpact   []RegulatoryViolation `json:"regulatory_impact"`
	MinimalFixSet      []string              `json:"minimal_fix_set"`
	PriorityFix        string                `json:"priority_fix"`
	BreakingNote       string                `json:"breaking_note"`
	MITRETechnique     string                `json:"mitre_technique"`
	MITRETactic        string                `json:"mitre_tactic"`
	KillChainPhase     string                `json:"kill_chain_phase"`
	AffectedResources  []string              `json:"affected_resources"`
}

// ChainStep is one step in an attack chain narrative.
type ChainStep struct {
	Number    int    `json:"number"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	Technical string `json:"technical"`
	Technique string `json:"technique"`  // MITRE technique ID
	EnabledBy string `json:"enabled_by"` // rule_id of finding that enables this step
	Gain      string `json:"gain"`
}

// BlastRadiusDetail describes the impact if the chain is exploited.
type BlastRadiusDetail struct {
	InitialAccess      string   `json:"initial_access"`
	LateralMovement    string   `json:"lateral_movement"`
	MaxPrivilege       string   `json:"max_privilege"`
	DataAtRisk         []string `json:"data_at_risk"`
	ServicesAtRisk     []string `json:"services_at_risk"`
	EstimatedScopePerc string   `json:"estimated_scope_perc"`
}

// RegulatoryViolation is a single compliance framework breach the chain creates.
type RegulatoryViolation struct {
	Framework string `json:"framework"`
	Control   string `json:"control"`
	Impact    string `json:"impact"`
}
