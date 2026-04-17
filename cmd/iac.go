package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/vatsayanvivek/argus/internal/iac"
)

var (
	iacOutput           string
	iacOutputDir        string
	iacFailOnSeverity   string
	iacPseudoSub        string
	iacPseudoTenant     string
	iacFormat           string
)

var iacCmd = &cobra.Command{
	Use:   "iac <iac-artifact.json>",
	Short: "Scan Terraform / ARM / Bicep / ARM what-if for Azure misconfigurations",
	Long: `Run the full ARGUS policy library against an Infrastructure-as-Code artifact.

ARGUS auto-detects the input format from the JSON envelope and
evaluates the same 201 policies that 'argus scan' uses against the
planned state.

Supported inputs:

  Terraform plan (terraform show -json plan.out):
    terraform plan -out plan.out
    terraform show -json plan.out > plan.json
    argus iac plan.json

  ARM template (hand-written or from bicep build):
    bicep build main.bicep              # emits main.json
    argus iac main.json

  ARM what-if (preview of a live deployment's effect):
    az deployment group what-if --output json \
       --resource-group rg --template-file main.bicep > whatif.json
    argus iac whatif.json

Findings reference the source address (Terraform) or ARM resource ID
(ARM/Bicep/what-if) so they point back to the offending declaration.

Use --format to force a specific parser if auto-detection is wrong
for your input.

Exit codes:
  0  - scan completed, no findings at or above --fail-on
  1  - scan could not run (IO/parse/policy error)
  2  - scan completed, gate tripped by finding severity`,
	Args: cobra.ExactArgs(1),
	RunE: runIaC,
}

func init() {
	iacCmd.Flags().StringVar(&iacOutput, "output", "text", "Output format: text|json|sarif")
	iacCmd.Flags().StringVar(&iacOutputDir, "output-dir", "./argus-output", "Directory for json/sarif artifacts")
	iacCmd.Flags().StringVar(&iacFailOnSeverity, "fail-on", "HIGH", "Severity floor that flips exit code to 2: CRITICAL|HIGH|MEDIUM|LOW|NONE")
	iacCmd.Flags().StringVar(&iacPseudoSub, "subscription", "00000000-0000-0000-0000-000000000000", "Pseudo subscription ID shown in the report (plan has no real ID yet)")
	iacCmd.Flags().StringVar(&iacPseudoTenant, "tenant", "00000000-0000-0000-0000-000000000000", "Pseudo tenant ID shown in the report")
	iacCmd.Flags().StringVar(&iacFormat, "format", "auto", "IaC input format: auto|terraform|arm|bicep|whatif (auto detects from file envelope)")
	rootCmd.AddCommand(iacCmd)
}

func runIaC(cmd *cobra.Command, args []string) error {
	planPath := args[0]

	PrintCompactBanner(os.Stdout)
	bold := color.New(color.Bold).SprintFunc()
	fmt.Printf("%s %s\n", bold("IaC scan"), planPath)

	result, err := iac.ScanWithFormat(planPath, iacFormat, iacPseudoSub, iacPseudoTenant)
	if err != nil {
		return err
	}

	switch strings.ToLower(iacOutput) {
	case "json":
		if err := writeIaCJSON(result); err != nil {
			return err
		}
	case "sarif":
		if err := writeIaCSARIF(result); err != nil {
			return err
		}
	case "text", "":
		printIaCText(result)
	default:
		return fmt.Errorf("unknown --output value %q (expected text|json|sarif)", iacOutput)
	}

	if gateTripped(result.Counts, iacFailOnSeverity) {
		return &CIGateError{
			Message: fmt.Sprintf("IaC scan gate: %d CRITICAL / %d HIGH / %d MEDIUM findings at or above --fail-on=%s",
				result.Counts.Critical, result.Counts.High, result.Counts.Medium, strings.ToUpper(iacFailOnSeverity)),
			ExitCode: 2,
		}
	}
	return nil
}

// printIaCText prints a concise, human-readable summary to stdout.
// The format header + resource count come from whichever parser ran;
// for Terraform we use PlannedResources(), for ARM/Bicep/what-if we
// use the snapshot resource count.
func printIaCText(r *iac.Result) {
	red := color.New(color.FgRed, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow, color.Bold).SprintFunc()
	green := color.New(color.FgGreen, color.Bold).SprintFunc()
	dim := color.New(color.Faint).SprintFunc()

	formatLabel := iacFormatLabel(r)
	resourceCount := 0
	if r.Plan != nil {
		resourceCount = len(r.Plan.PlannedResources())
	} else if r.Snapshot != nil {
		resourceCount = len(r.Snapshot.Resources)
	}

	fmt.Printf("\n%s format: %s\n", dim("→"), formatLabel)
	fmt.Printf("%s %d resources evaluated\n", dim("→"), resourceCount)
	fmt.Printf("%s %d findings (%s CRITICAL, %s HIGH, %d MEDIUM, %d LOW)\n\n",
		dim("→"),
		len(r.Findings),
		red(fmt.Sprintf("%d", r.Counts.Critical)),
		yellow(fmt.Sprintf("%d", r.Counts.High)),
		r.Counts.Medium,
		r.Counts.Low,
	)

	if len(r.Findings) == 0 {
		fmt.Println(green("✓ No policy violations in the planned state."))
		return
	}

	// Group findings by severity bucket and print.
	grouped := map[string][]string{}
	for _, f := range r.Findings {
		// Extract the terraform address from the synthesised resource ID
		// (everything after the last slash).
		tfAddr := f.ResourceName
		if slash := strings.LastIndex(f.ResourceID, "/"); slash >= 0 {
			tfAddr = f.ResourceID[slash+1:]
		}
		line := fmt.Sprintf("  %-12s %-18s %s  %s", f.Severity, f.ID, tfAddr, f.Title)
		grouped[f.Severity] = append(grouped[f.Severity], line)
	}

	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		lines := grouped[sev]
		if len(lines) == 0 {
			continue
		}
		sort.Strings(lines)
		switch sev {
		case "CRITICAL":
			fmt.Println(red(sev))
		case "HIGH":
			fmt.Println(yellow(sev))
		default:
			fmt.Println(dim(sev))
		}
		for _, l := range lines {
			fmt.Println(l)
		}
		fmt.Println()
	}
}

func writeIaCJSON(r *iac.Result) error {
	if err := os.MkdirAll(iacOutputDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(iacOutputDir, "argus-iac.json")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	meta := map[string]interface{}{
		"format": iacFormatLabel(r),
	}
	if r.Plan != nil {
		meta["terraform_version"] = r.Plan.TerraformVersion
		meta["plan_format_version"] = r.Plan.FormatVersion
		meta["resources_scanned"] = len(r.Plan.PlannedResources())
	} else if r.Snapshot != nil {
		meta["resources_scanned"] = len(r.Snapshot.Resources)
	}

	payload := map[string]interface{}{
		"plan":     meta,
		"counts":   r.Counts,
		"findings": r.Findings,
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(payload); err != nil {
		return err
	}
	fmt.Printf("→ wrote %s\n", path)
	return nil
}

// iacFormatLabel returns a human-readable format name derived from
// the Result's Format field. Falls back to inspecting r.Plan/r.Snapshot
// when Format is empty (defensive guard for results produced by code
// paths that skipped setting it).
func iacFormatLabel(r *iac.Result) string {
	switch r.Format {
	case string(iac.FormatTerraform):
		return "Terraform plan"
	case string(iac.FormatARM):
		return "ARM template"
	case string(iac.FormatBicep):
		return "Bicep (compiled to ARM)"
	case string(iac.FormatARMWhatIf):
		return "ARM what-if"
	}
	if r.Plan != nil {
		return "Terraform plan"
	}
	return "unknown"
}

// writeIaCSARIF emits a minimal SARIF 2.1.0 file suitable for upload to
// the GitHub Security tab. We intentionally do not reuse the full scan
// reporter because IaC findings lack some fields (chain participation,
// remediation snippets keyed to real resource IDs) and pre-deployment
// users typically only need rule id + severity + location.
func writeIaCSARIF(r *iac.Result) error {
	if err := os.MkdirAll(iacOutputDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(iacOutputDir, "argus-iac.sarif")

	rules := map[string]map[string]interface{}{}
	results := []map[string]interface{}{}

	for _, f := range r.Findings {
		if _, ok := rules[f.ID]; !ok {
			rules[f.ID] = map[string]interface{}{
				"id":               f.ID,
				"name":             f.Title,
				"shortDescription": map[string]interface{}{"text": f.Title},
				"fullDescription":  map[string]interface{}{"text": f.Description},
				"defaultConfiguration": map[string]interface{}{
					"level": sarifLevel(f.Severity),
				},
			}
		}
		results = append(results, map[string]interface{}{
			"ruleId":  f.ID,
			"level":   sarifLevel(f.Severity),
			"message": map[string]interface{}{"text": f.Detail},
			"locations": []map[string]interface{}{{
				"logicalLocations": []map[string]interface{}{{
					"name": f.ResourceName,
					"kind": "resource",
				}},
			}},
		})
	}

	ruleList := make([]map[string]interface{}, 0, len(rules))
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		ruleList = append(ruleList, rules[id])
	}

	doc := map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{{
			"tool": map[string]interface{}{
				"driver": map[string]interface{}{
					"name":           "ARGUS",
					"version":        version,
					"informationUri": "https://github.com/vatsayanvivek/argus",
					"rules":          ruleList,
				},
			},
			"results": results,
		}},
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return err
	}
	fmt.Printf("→ wrote %s\n", path)
	return nil
}

func sarifLevel(sev string) string {
	switch sev {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}

// gateTripped returns true iff the findings counts contain at least one
// entry at or above the named severity floor. "NONE" disables the gate.
func gateTripped(c iac.SeverityCounts, floor string) bool {
	switch strings.ToUpper(floor) {
	case "CRITICAL":
		return c.Critical > 0
	case "HIGH":
		return c.Critical+c.High > 0
	case "MEDIUM":
		return c.Critical+c.High+c.Medium > 0
	case "LOW":
		return c.Critical+c.High+c.Medium+c.Low > 0
	case "NONE", "":
		return false
	default:
		return c.Critical+c.High > 0
	}
}
