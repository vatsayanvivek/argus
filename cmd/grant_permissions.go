package cmd

// grant_permissions.go implements `argus grant-permissions` — a built-in
// bootstrap that creates an Azure AD service principal for ARGUS with the
// correct subscription + Microsoft Graph scopes.
//
// Why it exists:
//   Users who install ARGUS via a package manager (brew / scoop / winget) or
//   via a signed EXE don't have the helper shell scripts that ship in the
//   source tree. Rather than asking them to curl the script separately, we
//   embed both scripts into the binary and run the right one for their
//   platform. Same logic, zero extra download.

import (
	"embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

//go:embed grant_permissions_scripts/setup-graph-permissions.sh grant_permissions_scripts/setup-graph-permissions.ps1
var grantPermissionsScripts embed.FS

var (
	grantSubscription string
	grantTenant       string
	grantSPName       string
	grantShell        string
	grantDryRun       bool
)

var grantPermissionsCmd = &cobra.Command{
	Use:   "grant-permissions",
	Short: "Create the Azure AD service principal ARGUS needs, with the correct scopes",
	Long: `grant-permissions creates an Azure AD service principal for ARGUS and
assigns the roles + Microsoft Graph application permissions the scanner
needs. Runs entirely against the Azure CLI ('az') on your machine — no
data leaves your environment.

  argus grant-permissions --subscription <id> --tenant <id>
  argus grant-permissions --subscription <id> --tenant <id> --name my-argus-sp

Prerequisites:
  - Azure CLI ('az') on PATH. Install: https://aka.ms/InstallAzureCLI
  - You must be logged in as a Global Administrator or Privileged Role
    Administrator so admin consent can be granted for Graph permissions.
  - On bash/zsh systems: 'jq' on PATH.
  - On Windows: PowerShell 5.1+ (ships with the OS) or pwsh 7+.

The script is embedded in the argus binary — no separate download
required. The same script also ships as a release asset for users who
prefer to read it before running.`,
	RunE: runGrantPermissions,
}

func init() {
	grantPermissionsCmd.Flags().StringVar(&grantSubscription, "subscription", "", "Azure subscription ID (required)")
	grantPermissionsCmd.Flags().StringVar(&grantTenant, "tenant", "", "Azure tenant ID (required)")
	grantPermissionsCmd.Flags().StringVar(&grantSPName, "name", "argus-scanner", "Name for the service principal")
	grantPermissionsCmd.Flags().StringVar(&grantShell, "shell", "", "Force a specific shell: 'bash' or 'powershell'. Default: auto-detect.")
	grantPermissionsCmd.Flags().BoolVar(&grantDryRun, "dry-run", false, "Print the commands that would run without executing")
	_ = grantPermissionsCmd.MarkFlagRequired("subscription")
	_ = grantPermissionsCmd.MarkFlagRequired("tenant")
	rootCmd.AddCommand(grantPermissionsCmd)
}

func runGrantPermissions(cmd *cobra.Command, args []string) error {
	bold := color.New(color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	shell := grantShell
	if shell == "" {
		shell = detectShell()
	}

	fmt.Printf("%s  creating service principal %s\n", bold("ARGUS grant-permissions"), cyan(grantSPName))
	fmt.Printf("  subscription : %s\n", grantSubscription)
	fmt.Printf("  tenant       : %s\n", grantTenant)
	fmt.Printf("  shell        : %s\n", shell)
	fmt.Println()

	// What scopes we're about to request — transparent up-front so the
	// admin running this knows exactly what consent they are granting.
	fmt.Println(bold("Azure RBAC roles (subscription scope):"))
	fmt.Println("  • Reader           — read every resource for posture analysis")
	fmt.Println("  • Security Reader  — read Defender for Cloud findings + secure score")
	fmt.Println()
	fmt.Println(bold("Microsoft Graph application permissions:"))
	for _, p := range grantedGraphScopes {
		fmt.Printf("  • %-36s — %s\n", cyan(p.ID), p.Purpose)
	}
	fmt.Println()
	fmt.Println(yellow("Each permission is explained below. You will be asked to consent to"))
	fmt.Println(yellow("each one as admin. Re-running this command is safe — it's idempotent."))
	fmt.Println()

	scriptPath, err := extractScript(shell)
	if err != nil {
		return fmt.Errorf("extract embedded script: %w", err)
	}
	defer func() { _ = os.Remove(scriptPath) }()

	shellCmd, shellArgs := buildShellCommand(shell, scriptPath, grantSubscription, grantTenant, grantSPName)

	if grantDryRun {
		fmt.Printf("%s %s %v\n", bold("Would run:"), shellCmd, shellArgs)
		return nil
	}

	proc := exec.Command(shellCmd, shellArgs...)
	proc.Stdin = os.Stdin
	proc.Stdout = os.Stdout
	proc.Stderr = os.Stderr
	if err := proc.Run(); err != nil {
		return fmt.Errorf("%s script failed: %w", shell, err)
	}

	fmt.Println()
	fmt.Println(color.GreenString("✓ Service principal ready. Validate with:"))
	fmt.Printf("  argus check-permissions --tenant %s\n", grantTenant)
	return nil
}

// grantedGraphScopes documents every Microsoft Graph application permission
// that the bootstrap script requests, plus why ARGUS needs it. Rendered by
// the command so the admin knows exactly what they're consenting to.
var grantedGraphScopes = []struct {
	ID      string
	Purpose string
}{
	{"Directory.Read.All", "Read users, groups, service principals for every identity rule"},
	{"Application.Read.All", "Detect App Registration takeover chains (CHAIN-002)"},
	{"Policy.Read.All", "Enumerate Conditional Access + Authentication policies"},
	{"RoleManagement.Read.Directory", "Read Entra directory role assignments + PIM schedules"},
	{"AccessReview.Read.All", "Verify access reviews exist for privileged roles"},
	{"AuditLog.Read.All", "Read sign-in + audit logs for stale-account detection"},
	{"Group.Read.All", "Walk nested group membership for privilege-path analysis"},
	{"GroupMember.Read.All", "Transitive member expansion — the #1 way Owner access hides"},
}

// detectShell picks the interpreter to use based on the host OS. macOS and
// Linux get bash; Windows prefers pwsh (PowerShell 7) if available, falling
// back to Windows PowerShell 5.1.
func detectShell() string {
	if runtime.GOOS == "windows" {
		return "powershell"
	}
	return "bash"
}

// extractScript writes the embedded shell / PowerShell script to a temp
// file and returns its path. Caller is responsible for removing it.
func extractScript(shell string) (string, error) {
	var name, ext string
	if shell == "powershell" || shell == "pwsh" {
		name, ext = "grant_permissions_scripts/setup-graph-permissions.ps1", ".ps1"
	} else {
		name, ext = "grant_permissions_scripts/setup-graph-permissions.sh", ".sh"
	}
	raw, err := grantPermissionsScripts.ReadFile(name)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "argus-grant-permissions-*"+ext)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(raw); err != nil {
		return "", err
	}
	if shell == "bash" || shell == "zsh" {
		_ = os.Chmod(f.Name(), 0o755)
	}
	return f.Name(), nil
}

// buildShellCommand picks the interpreter and its flags. We always invoke
// the script by path, not by piped content, so the user can see it in ps /
// Task Manager and know what's running.
func buildShellCommand(shell, scriptPath, sub, tenant, spName string) (string, []string) {
	switch shell {
	case "bash", "zsh":
		return shell, []string{scriptPath, sub, tenant, spName}
	case "powershell":
		// Prefer pwsh 7 when present; fall back to classic PowerShell.
		if _, err := exec.LookPath("pwsh"); err == nil {
			return "pwsh", []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath,
				"-SubscriptionId", sub, "-TenantId", tenant, "-SpnName", spName}
		}
		return "powershell", []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath,
			"-SubscriptionId", sub, "-TenantId", tenant, "-SpnName", spName}
	case "pwsh":
		return "pwsh", []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath,
			"-SubscriptionId", sub, "-TenantId", tenant, "-SpnName", spName}
	}
	return "bash", []string{scriptPath, sub, tenant, spName}
}

// referenced to keep filepath importable while still logging the resolved
// script location in debug output.
var _ = filepath.Base
