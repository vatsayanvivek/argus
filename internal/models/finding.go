package models

// Finding is an enriched security finding from a Rego policy violation.
// Every field is populated either by the OPA evaluator or by the
// benchmark mapper which enriches with CSV metadata.
type Finding struct {
	ID                   string                 `json:"id"`
	Source               string                 `json:"source"` // argus-cis | argus-zt
	ResourceID           string                 `json:"resource_id"`
	ResourceType         string                 `json:"resource_type"`
	ResourceName         string                 `json:"resource_name"`
	ResourceGroup        string                 `json:"resource_group"`
	Location             string                 `json:"location"`
	Scope                string                 `json:"scope"` // tenant | subscription | resource-group | resource
	Severity             string                 `json:"severity"` // CRITICAL | HIGH | MEDIUM | LOW
	Pillar               string                 `json:"pillar"`   // Identity | Network | Workload | Data | Visibility
	CISRule              string                 `json:"cis_rule"`
	CISLevel             string                 `json:"cis_level"` // L1 | L2
	NIST80053Control     string                 `json:"nist_800_53_control"`
	NIST800207Tenet      string                 `json:"nist_800_207_tenet"`
	MITRETechnique       string                 `json:"mitre_technique"`
	MITRETactic          string                 `json:"mitre_tactic"`
	Frameworks           []string               `json:"frameworks"`
	Title                string                 `json:"title"`
	Description          string                 `json:"description"`
	Detail               string                 `json:"detail"`
	Evidence             map[string]interface{} `json:"evidence"`
	RemediationText      string                 `json:"remediation_text"`
	RemediationTerraform string                 `json:"remediation_terraform"`
	RemediationCLI       string                 `json:"remediation_cli"`
	EstimatedEffortHours int                    `json:"estimated_effort_hours"`
	BusinessImpact       string                 `json:"business_impact"`
	AttackScenario       string                 `json:"attack_scenario"`
	BlastRadius          string                 `json:"blast_radius"`
	ChainRole            string                 `json:"chain_role"` // ANCHOR | AMPLIFIER | ENABLER
	ParticipatesInChains []string               `json:"participates_in_chains"`
	ChainPriority        bool                   `json:"chain_priority"`
	// AffectedResources carries the extra resource IDs when N identical
	// findings are collapsed into one. The original ResourceID field
	// holds the first / canonical resource; everything else lives here.
	// Empty when the finding is a single-resource violation.
	AffectedResources []string `json:"affected_resources,omitempty"`
	// ComplianceMappings decorates the finding with control IDs from
	// every loaded compliance framework that maps this rule. Keys are
	// framework short names ("soc2", "hipaa", "pci-dss-4",
	// "iso-27001"); values are the list of control IDs within that
	// framework the rule satisfies. Empty when the finding's rule has
	// no mapping in any loaded pack.
	ComplianceMappings map[string][]string `json:"compliance_mappings,omitempty"`
}

// ScopeResource / ScopeResourceGroup / ScopeSubscription / ScopeTenant
// enumerate the Scope field values. Constants keep grep-ability.
const (
	ScopeTenant        = "tenant"
	ScopeSubscription  = "subscription"
	ScopeResourceGroup = "resource-group"
	ScopeResource      = "resource"
)
