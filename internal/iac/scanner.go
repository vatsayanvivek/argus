package iac

import (
	"fmt"
	"os"
	"strings"

	"github.com/vatsayanvivek/argus/internal/engine"
	"github.com/vatsayanvivek/argus/internal/models"
)

// newEngineForIaC is the single engine-construction entry point every
// IaC format uses. Kept narrow so if a future policy-engine change
// requires IaC-specific setup (smaller embedding, different filter),
// we only change it here.
func newEngineForIaC() (*engine.OPAEngine, error) {
	eng, err := engine.NewOPAEngine()
	if err != nil {
		return nil, fmt.Errorf("initialise policy engine: %w", err)
	}
	return eng, nil
}

// filterToPlanScope keeps only findings whose resource ID contains one
// of the terraform addresses from the parsed plan. Synthesised IDs look
// like ".../providers/<armType>/<tf.address>", so a substring match on
// the address is sufficient and correct.
func filterToPlanScope(findings []models.Finding, plan *Plan) []models.Finding {
	addresses := make(map[string]struct{}, len(plan.ResourceChanges))
	for _, rc := range plan.PlannedResources() {
		addresses[rc.Address] = struct{}{}
	}
	if len(addresses) == 0 {
		return nil
	}
	out := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		for addr := range addresses {
			if strings.Contains(f.ResourceID, addr) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// Result is the return shape of Scan. It carries the translated
// snapshot (useful for debugging and JSON output), the findings the
// policy engine produced, and some top-line counters for the terminal
// summary.
//
// Format records which IaC artifact the Result came from so the CLI
// can render an accurate summary header ("Terraform plan", "ARM
// template", "ARM what-if"). Empty string means the Result pre-dates
// the multi-format scanner; callers should fall back to checking
// whether Plan is non-nil to infer Terraform.
type Result struct {
	Plan     *Plan
	Snapshot *models.AzureSnapshot
	Findings []models.Finding
	Format   string

	Counts SeverityCounts
}

// SeverityCounts tallies findings by severity bucket.
type SeverityCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
}

// Scan reads an IaC artifact (Terraform plan JSON, ARM template JSON,
// Bicep-compiled ARM JSON, or ARM what-if JSON), translates it into a
// synthetic Azure snapshot, and evaluates the OPA/Rego policy library
// against it.
//
// The format is auto-detected from the JSON envelope (see
// DetectFormat). Callers that need to force a specific parser can use
// ScanWithFormat.
//
// `pseudoSub` and `pseudoTenant` are placeholder identifiers used to
// fill the snapshot's subscription/tenant fields; they are purely
// cosmetic and appear only in the output reports.
func Scan(planPath, pseudoSub, pseudoTenant string) (*Result, error) {
	return ScanWithFormat(planPath, "", pseudoSub, pseudoTenant)
}

// ScanWithFormat is Scan with an explicit format override. Accepts:
//   "" or "auto"   → auto-detect
//   "terraform"    → Terraform plan JSON
//   "arm", "bicep" → ARM template JSON (Bicep-compiled JSON is identical)
//   "whatif", "arm-whatif" → ARM deployment what-if output
//
// Any other value returns an error. The user-provided format string
// overrides detection even when the envelope disagrees — useful for
// paths where the user knows the file is a what-if response even
// though it superficially resembles an ARM template.
func ScanWithFormat(planPath, formatOverride, pseudoSub, pseudoTenant string) (*Result, error) {
	f, err := os.Open(planPath)
	if err != nil {
		return nil, fmt.Errorf("open iac file: %w", err)
	}
	defer f.Close()

	fmtResolved, payload, err := resolveFormat(f, formatOverride)
	if err != nil {
		return nil, err
	}

	switch fmtResolved {
	case FormatTerraform:
		return scanTerraformBytes(payload, pseudoSub, pseudoTenant)
	case FormatARM, FormatBicep:
		res, err := ScanARMBytes(payload, pseudoSub, pseudoTenant)
		if err != nil {
			return nil, err
		}
		res.Format = string(fmtResolved)
		return res, nil
	case FormatARMWhatIf:
		res, err := ScanWhatIfBytes(payload, pseudoSub, pseudoTenant)
		if err != nil {
			return nil, err
		}
		res.Format = string(fmtResolved)
		return res, nil
	default:
		return nil, fmt.Errorf("could not identify IaC format for %s; use --format to force one of terraform|arm|bicep|whatif", planPath)
	}
}

// resolveFormat applies the user's format override (if any) and falls
// back to auto-detection otherwise. Returns the decided format and
// the raw file payload so the caller doesn't re-read from disk.
func resolveFormat(f *os.File, override string) (Format, []byte, error) {
	// Read the full file once.
	detected, payload, detectErr := DetectFormat(f)

	override = strings.ToLower(strings.TrimSpace(override))
	switch override {
	case "", "auto":
		if detectErr != nil {
			return FormatUnknown, payload, detectErr
		}
		return detected, payload, nil
	case "terraform", "terraform-plan", "tfplan":
		return FormatTerraform, payload, nil
	case "arm", "arm-template":
		return FormatARM, payload, nil
	case "bicep":
		return FormatBicep, payload, nil
	case "whatif", "arm-whatif", "what-if":
		return FormatARMWhatIf, payload, nil
	default:
		return FormatUnknown, payload, fmt.Errorf("unsupported --format %q (expected auto|terraform|arm|bicep|whatif)", override)
	}
}

// scanTerraformBytes is the Terraform-plan pipeline split out so the
// format dispatch in ScanWithFormat can reuse it without re-opening
// the file.
func scanTerraformBytes(payload []byte, pseudoSub, pseudoTenant string) (*Result, error) {
	plan, err := ParsePlan(strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}

	snap := Translate(plan, pseudoSub, pseudoTenant)

	eng, err := engine.NewOPAEngine()
	if err != nil {
		return nil, fmt.Errorf("initialise policy engine: %w", err)
	}

	allFindings, err := eng.Evaluate(snap, "all")
	if err != nil {
		return nil, fmt.Errorf("evaluate policies: %w", err)
	}

	// Restrict findings to ones whose resource ID contains a terraform
	// address from the plan. Subscription- or tenant-scoped rules (no
	// CAP, no break-glass, no Defender plans) fire against the empty
	// identity snapshot and are just noise pre-deployment: the plan
	// cannot configure tenant posture.
	findings := filterToPlanScope(allFindings, plan)

	res := &Result{Plan: plan, Snapshot: snap, Findings: findings, Format: string(FormatTerraform)}
	for _, f := range findings {
		switch f.Severity {
		case "CRITICAL":
			res.Counts.Critical++
		case "HIGH":
			res.Counts.High++
		case "MEDIUM":
			res.Counts.Medium++
		case "LOW":
			res.Counts.Low++
		}
	}
	return res, nil
}
