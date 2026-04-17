package models

// DriftFinding is the result of permission drift analysis comparing
// granted RBAC actions vs actually used actions from Activity Log.
type DriftFinding struct {
	IdentityARN      string   `json:"identity_arn"`
	IdentityName     string   `json:"identity_name"`
	IdentityType     string   `json:"identity_type"` // User | ServicePrincipal | ManagedIdentity
	RoleName         string   `json:"role_name"`
	RoleResolved     bool     `json:"role_resolved"` // true when the role definition was found in the catalogue
	AnalysisWindowDays int    `json:"analysis_window_days"`
	GrantedActions   []string `json:"granted_actions"`
	UsedActions      []string `json:"used_actions"`
	UnusedActions    []string `json:"unused_actions"`
	UnusedPercentage float64  `json:"unused_percentage"`
	BlastRadius      string   `json:"blast_radius"` // CRITICAL | HIGH | MEDIUM | LOW
	LastActivity     string   `json:"last_activity"`
	Recommendation   string   `json:"recommendation"`
}
