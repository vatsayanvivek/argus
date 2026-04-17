package models

import "time"

// AzureSnapshot is the complete environment state collected by ARGUS.
type AzureSnapshot struct {
	SubscriptionID     string
	SubscriptionName   string
	TenantID           string
	ScanTime           time.Time
	CollectionMode     string // full | partial | minimal
	Resources          []AzureResource
	Identity           IdentitySnapshot
	DefenderFindings   []DefenderFinding
	DefenderPlans      map[string]string // service -> "Free" | "Standard"
	SecureScore        float64
	PolicyCompliance   []PolicyResult
	ActivityLog        []ActivityEvent
	DiagnosticSettings map[string]bool // resource_id -> has settings
	NetworkTopology    NetworkSnapshot
	CollectionErrors   []string // services that failed
	// GraphPermissionsLimited is set when one or more Microsoft Graph
	// API endpoints returned 401/403 during identity collection. When
	// true, several identity-related rules (notably CHAIN-002 /
	// zt_id_011 / cis_1_15 — App Registration takeover) cannot be
	// evaluated and the report must surface a prominent warning so the
	// user is not given a false sense of security.
	GraphPermissionsLimited bool
	// GraphPermissionsMissing lists the human-readable scope names
	// that the scanning identity did not have. Empty when full Graph
	// access was available.
	GraphPermissionsMissing []string
}

// AzureResource is a single resource discovered via Resource Graph.
type AzureResource struct {
	ID            string
	Name          string
	Type          string
	Location      string
	ResourceGroup string
	Properties    map[string]interface{}
	Tags          map[string]string
	SKU           string
	Kind          string
}

// IdentitySnapshot is everything from Azure AD relevant to security.
//
// RoleAssignments are Entra *directory*-scope roles (Global Admin,
// Application Administrator, etc.) retrieved via Microsoft Graph.
// AzureRBACAssignments are Azure *resource*-scope role assignments
// (Contributor, Owner, Reader on subscriptions, RGs, and individual
// resources) retrieved via the ARM Authorization API. They are kept
// in separate slices because existing rules historically assume
// input.role_assignments == directory assignments, and merging the
// two would silently change their semantics.
type IdentitySnapshot struct {
	Users                []AADUser
	Groups               []AADGroup
	ServicePrincipals    []ServicePrincipal
	AppRegistrations     []AppRegistration
	ManagedIdentities    []ManagedIdentity
	ConditionalAccess    []ConditionalAccessPolicy
	PIMAssignments       []PIMAssignment
	RoleAssignments      []RoleAssignment
	AzureRBACAssignments []RoleAssignment
	AccessReviews        []AccessReview
	TenantSettings       TenantSettings
}

// AADGroup is an Azure AD (Entra) group. Members holds the Entra object
// IDs of direct members — both users and other groups. The pathfinder
// walks these transitively to discover privilege paths that inherit
// through nested group membership (the #1 cause of "how did X end up
// with Owner?" incidents).
type AADGroup struct {
	ID              string
	DisplayName     string
	SecurityEnabled bool
	MailEnabled     bool
	Members         []string // direct member object IDs (users, SPs, or other groups)
}

// AADUser is an Azure AD user object.
type AADUser struct {
	ID                    string
	DisplayName           string
	UserPrincipalName     string
	AccountEnabled        bool
	UserType              string // Member | Guest
	AssignedRoles         []string
	OnPremisesSyncEnabled bool
	LastSignInDateTime    string
	MFAEnabled            bool
}

// ServicePrincipal is an Azure AD service principal.
type ServicePrincipal struct {
	ID                   string
	DisplayName          string
	AppID                string
	ServicePrincipalType string
	PasswordCredentials  []Credential
	KeyCredentials       []Credential
	AppRoles             []string
	AccountEnabled       bool
}

// Credential is a SP/App password or key credential.
type Credential struct {
	KeyID         string
	StartDateTime string
	EndDateTime   string // empty / null means never expires
	DisplayName   string
}

// AppRegistration is an Azure AD application registration.
type AppRegistration struct {
	ID                     string
	DisplayName            string
	AppID                  string
	PasswordCredentials    []Credential
	RequiredResourceAccess []ResourceAccess
}

// ResourceAccess is a Graph API resource access block.
type ResourceAccess struct {
	ResourceAppID string
	Permissions   []Permission
}

// Permission is a single Graph API permission entry.
// Type "Role" = application permission (dangerous).
// Type "Scope" = delegated permission (less dangerous).
type Permission struct {
	ID   string
	Type string
}

// ManagedIdentity is an Azure managed identity.
type ManagedIdentity struct {
	ID          string
	Name        string
	Type        string // SystemAssigned | UserAssigned
	PrincipalID string
	ResourceIDs []string // resources that use this identity
}

// ConditionalAccessPolicy is a CAP definition.
type ConditionalAccessPolicy struct {
	ID            string
	DisplayName   string
	State         string // enabled | disabled | enabledForReportingButNotEnforced
	Conditions    map[string]interface{}
	GrantControls map[string]interface{}
}

// PIMAssignment is a PIM role assignment (eligible or active). Scope
// carries the directory scope (usually "/" for tenant-wide roles like
// Global Admin, occasionally "/administrativeUnits/<id>" for AU-scoped
// roles). The pathfinder uses both Eligible and Active assignments to
// synthesise has_role edges — Active edges carry full role weight;
// Eligible edges are slightly down-weighted because activation is an
// extra step an attacker must clear.
type PIMAssignment struct {
	ID               string
	RoleDefinitionID string
	RoleName         string
	PrincipalID      string
	PrincipalType    string // User | Group | ServicePrincipal
	PrincipalName    string
	AssignmentType   string // Eligible | Active
	Scope            string
	StartDateTime    string
	EndDateTime      string
}

// RoleAssignment is a standard Azure RBAC role assignment.
type RoleAssignment struct {
	ID               string
	RoleDefinitionID string
	RoleName         string
	PrincipalID      string
	PrincipalType    string // User | Group | ServicePrincipal
	Scope            string
}

// AccessReview is an Azure AD access review definition.
type AccessReview struct {
	ID          string
	DisplayName string
	Status      string
	Reviewers   []string
	Scope       string
}

// TenantSettings holds tenant-level identity policies.
type TenantSettings struct {
	LegacyAuthEnabled            bool
	GuestUserPermissions         string // None | LimitedAccess | FullAccess
	GuestInviteRestrictions      string
	CrossTenantAccessUnrestricted bool
	PasswordResetNotification    bool
}

// DefenderFinding is a Microsoft Defender for Cloud recommendation.
type DefenderFinding struct {
	ID             string
	Name           string
	DisplayName    string
	Severity       string
	Status         string
	ResourceID     string
	Description    string
	RemediationURL string
}

// PolicyResult is the compliance state of an Azure Policy assignment.
type PolicyResult struct {
	PolicyName            string
	PolicyAssignmentID    string
	ComplianceState       string // Compliant | NonCompliant | NotStarted
	NonCompliantCount     int
	NonCompliantResources []string
}

// ActivityEvent is one entry from Azure Monitor Activity Log.
type ActivityEvent struct {
	OperationName string
	Caller        string
	ResourceID    string
	ResourceType  string
	Status        string // Succeeded | Failed
	Timestamp     time.Time
	Category      string
}

// NetworkSnapshot is the network topology view used by chain correlation.
type NetworkSnapshot struct {
	VNets     []VirtualNetwork
	Subnets   []Subnet
	NSGs      []NetworkSecurityGroup
	PublicIPs []PublicIP
	Peerings  []VNetPeering
}

// VirtualNetwork is an Azure virtual network.
type VirtualNetwork struct {
	ID            string
	Name          string
	AddressSpace  []string
	ResourceGroup string
	DDoSEnabled   bool
}

// Subnet is a VNet subnet.
type Subnet struct {
	ID            string
	Name          string
	VNetID        string
	CIDR          string
	NSGID         string // empty if no NSG attached
	HasNSG        bool
}

// NetworkSecurityGroup is an NSG with its rules.
type NetworkSecurityGroup struct {
	ID            string
	Name          string
	ResourceGroup string
	InboundRules  []NSGRule
	OutboundRules []NSGRule
	FlowLogsEnabled bool
}

// NSGRule is one inbound or outbound NSG rule.
type NSGRule struct {
	Name                 string
	Protocol             string
	Direction            string // Inbound | Outbound
	Access               string // Allow | Deny
	Priority             int
	SourceAddressPrefix  string
	SourcePortRange      string
	DestinationAddressPrefix string
	DestinationPortRange string
}

// PublicIP is an Azure public IP address resource.
type PublicIP struct {
	ID            string
	Name          string
	IPAddress     string
	AssociatedTo  string // resource ID this is attached to
}

// VNetPeering is a virtual network peering link.
type VNetPeering struct {
	ID         string
	Name       string
	SourceVNet string
	RemoteVNet string
	State      string
}
