package engine

import "io/fs"

// PoliciesFS exposes the embedded policy tree so other packages (for
// example a test harness or a policy-list command) can introspect what
// was bundled into the binary. All actual policy loading happens in
// NewOPAEngine.
func PoliciesFS() fs.FS {
	return policiesFS
}
