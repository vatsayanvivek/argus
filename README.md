# ARGUS — Azure Attack Chain Analyzer

> **Find the blindspots attackers chain together.**
> An open-source, source-available Azure security scanner.

[![License: PolyForm Strict 1.0.0](https://img.shields.io/badge/license-PolyForm%20Strict%201.0.0-blue.svg)](LICENSE)
[![Source Available](https://img.shields.io/badge/source-available-green.svg)](#license)
[![Built with Go](https://img.shields.io/badge/built%20with-Go%201.22-00ADD8.svg)](https://golang.org)
[![Powered by OPA / Rego](https://img.shields.io/badge/policies-OPA%20%2F%20Rego-7B2D8E.svg)](https://www.openpolicyagent.org)

---

ARGUS answers one question most cloud security tools don't:

> **Which misconfigurations in my Azure environment combine together into real exploitation chains — and what exact path would an attacker take?**

Other scanners list individual findings. ARGUS correlates them into **51 attack chain patterns** and tells you the 5 fixes that break the most chains.

No agent. No SaaS. No data leaves your machine.

---

## Table of contents

- [Features](#features)
- [Install in 60 seconds](#install-in-60-seconds)
- [Run your first scan](#run-your-first-scan)
- [Authentication](#authentication)
- [Examples](#examples)
- [IaC pre-deployment scanning](#iac-pre-deployment-scanning)
- [Graph-based chain discovery](#graph-based-chain-discovery)
- [Command reference](#command-reference)
- [CI/CD integration](#cicd-integration)
- [Configuration file](#configuration-file)
- [Webhooks](#webhooks)
- [Output formats](#output-formats)
- [The 51 attack chains](#the-51-attack-chains)
- [The 201 rules](#the-201-rules)
- [Suppressions](#suppressions-argusignore)
- [Build from source](#build-from-source)
- [License](#license)

---

## Features

- **201 rules** — CIS Microsoft Azure Foundations Benchmark v2.0 + custom Zero Trust rules mapped to the 5 NIST SP 800-207 pillars.
- **51 hand-authored attack chain patterns** — correlates findings across rules into personalized narratives that name your actual resources, user counts, and configuration gaps.
- **Graph-based chain discovery** — beyond the 51 patterns, a pathfinder builds a principal/resource/RBAC graph and walks it to surface attack paths no hand-authored rule would ever catch (DISC-* chains).
- **IaC pre-deployment scanning** — run the same 201 policies against a Terraform plan JSON before you `apply`, so a misconfiguration fails CI instead of reaching production.
- **Dollar-denominated risk quantification** — FAIR model annualized loss expectancy per chain, breach probability estimates, and remediation ROI rankings.
- **Permission drift analysis** — compares granted RBAC actions to actually-used actions in the Activity Log. Finds the service principals granted 847 actions that used 12.
- **Pareto Quick Wins** — the top 5 fixes that break the most attack chains, so you know exactly where to start.
- **Trend mode** — automatic score delta, new findings, resolved findings, and new chains vs. your last scan.
- **Continuous monitoring** — daemon mode that fires Slack / Teams / webhook alerts when score drifts.
- **HTTP API server** — submit scans, poll status, retrieve reports programmatically.
- **CI/CD gates** — fail pipelines on CRITICAL findings, chain count, or score thresholds.
- **Suppressions** — `.argusignore` YAML file with audit trail (rule, resource, reason, approver, expiry).
- **Tenant-wide scanning** — discover and scan every subscription in your tenant in parallel, with a rolled-up worst-first ranking.
- **Four output formats** — self-contained HTML (consulting-deliverable), JSON, SARIF 2.1.0, and a zipped compliance evidence bundle for auditors.
- **Zero per-service code** — Azure Resource Graph is the universal collector. New Azure services are automatically covered.
- **Every rule is auditable** — all 201 checks live as OPA/Rego policies in `policies/`, not buried in Go.

Every finding ships with:
- The exact resource ID and resource group that failed
- Plain-English business impact
- Which attack chains it participates in
- A Terraform snippet to fix it (with real resource names substituted)
- An `az` CLI command to fix it
- CIS rule, NIST 800-53 control, NIST 800-207 tenet, and MITRE ATT&CK technique mapping

---

## Install in 60 seconds

Pick your platform — every block below is **copy-paste ready**. Pre-built binaries for the latest release live at <https://github.com/vatsayanvivek/argus/releases/latest>.

<details open>
<summary><b>🍎 macOS (Apple Silicon — M1/M2/M3/M4)</b></summary>

```bash
# 1. Download
curl -L -o argus https://github.com/vatsayanvivek/argus/releases/latest/download/argus-darwin-arm64

# 2. Make it executable and move onto your PATH
chmod +x argus
sudo mv argus /usr/local/bin/argus

# 3. Verify it runs
argus --version

# 4. (Recommended) Verify the SHA256
curl -L -o SHA256SUMS https://github.com/vatsayanvivek/argus/releases/latest/download/SHA256SUMS
shasum -a 256 /usr/local/bin/argus     # compare against the darwin-arm64 line in SHA256SUMS
```

If macOS Gatekeeper blocks the first run, right-click the binary in Finder → Open once, or run:

```bash
xattr -d com.apple.quarantine /usr/local/bin/argus
```
</details>

<details>
<summary><b>🍎 macOS (Intel x86_64)</b></summary>

```bash
curl -L -o argus https://github.com/vatsayanvivek/argus/releases/latest/download/argus-darwin-amd64
chmod +x argus
sudo mv argus /usr/local/bin/argus
argus --version

# SHA256 check
curl -L -o SHA256SUMS https://github.com/vatsayanvivek/argus/releases/latest/download/SHA256SUMS
shasum -a 256 /usr/local/bin/argus
```
</details>

<details>
<summary><b>🐧 Linux (x86_64 / amd64)</b></summary>

```bash
# 1. Download
curl -L -o argus https://github.com/vatsayanvivek/argus/releases/latest/download/argus-linux-amd64

# 2. Install onto PATH
chmod +x argus
sudo mv argus /usr/local/bin/argus

# 3. Verify
argus --version

# 4. SHA256 check
curl -L -o SHA256SUMS https://github.com/vatsayanvivek/argus/releases/latest/download/SHA256SUMS
sha256sum /usr/local/bin/argus   # compare to the linux-amd64 line in SHA256SUMS
```
</details>

<details>
<summary><b>🐧 Linux (arm64 — e.g. AWS Graviton, Raspberry Pi 4+)</b></summary>

```bash
curl -L -o argus https://github.com/vatsayanvivek/argus/releases/latest/download/argus-linux-arm64
chmod +x argus
sudo mv argus /usr/local/bin/argus
argus --version
```
</details>

<details>
<summary><b>🪟 Windows (PowerShell — amd64)</b></summary>

Run PowerShell **as your normal user** (not Administrator unless writing to Program Files):

```powershell
# 1. Pick an install dir and add it to your PATH once
$installDir = "$env:USERPROFILE\bin"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

# 2. Download the binary
Invoke-WebRequest `
  -Uri "https://github.com/vatsayanvivek/argus/releases/latest/download/argus-windows-amd64.exe" `
  -OutFile "$installDir\argus.exe"

# 3. Add %USERPROFILE%\bin to PATH for new shells (once)
[Environment]::SetEnvironmentVariable(
  "Path",
  [Environment]::GetEnvironmentVariable("Path", "User") + ";$installDir",
  "User"
)

# 4. Open a NEW PowerShell window, then verify
argus --version

# 5. SHA256 check
Invoke-WebRequest `
  -Uri "https://github.com/vatsayanvivek/argus/releases/latest/download/SHA256SUMS" `
  -OutFile "$installDir\SHA256SUMS"
Get-FileHash "$installDir\argus.exe" -Algorithm SHA256
# Compare the hex output to the windows-amd64 line inside SHA256SUMS
```

If Windows SmartScreen blocks the binary, click **More info → Run anyway**, or unblock via PowerShell:

```powershell
Unblock-File "$env:USERPROFILE\bin\argus.exe"
```
</details>

<details>
<summary><b>🔨 Build from source (any platform — requires Go 1.22+)</b></summary>

```bash
git clone https://github.com/vatsayanvivek/argus.git
cd argus
make build
./argus --version

# Or build for every platform in one go:
make build-all        # writes to ./dist/
```

On Windows, if `make` isn't available, use the Go toolchain directly:

```powershell
go build -ldflags "-s -w -X main.Version=1.2.1" -o argus.exe .\main.go
```
</details>

### Prerequisites

| Tool | Why you need it | Install command |
|---|---|---|
| **Azure CLI** (`az`) | For `az login` — the easiest auth path | See below |
| **An Azure subscription** | To scan | Any — Free tier, Pay-As-You-Go, Enterprise |
| **Reader + Security Reader roles** on the subscription | Read resources, Defender findings, RBAC | Ask your Azure admin, or see the [SPN setup](#one-shot-spn-setup-recommended) below |

#### Install Azure CLI

<details>
<summary><b>macOS</b></summary>

```bash
brew install azure-cli
```
</details>

<details>
<summary><b>Linux (Debian/Ubuntu)</b></summary>

```bash
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```
</details>

<details>
<summary><b>Linux (RHEL/CentOS/Fedora)</b></summary>

```bash
sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
sudo dnf install azure-cli
```
</details>

<details>
<summary><b>Windows</b></summary>

```powershell
winget install --exact --id Microsoft.AzureCLI
# OR
Start-Process msiexec.exe -Wait -ArgumentList '/I https://aka.ms/installazurecliwindows /quiet'
```
</details>

After install, restart your shell and confirm with `az --version`.

---

## Run your first scan

The fastest possible path — five commands and you have a full HTML report.

<details open>
<summary><b>🍎 macOS / 🐧 Linux (bash/zsh)</b></summary>

```bash
# 1. Log in to Azure
az login

# 2. Pick the subscription you want to scan
az account set --subscription "<subscription-id>"

# 3. Grab the tenant and subscription IDs (reuse them in step 4)
az account show --query '{tenant: tenantId, sub: id}' -o table

# 4. Run a full scan
argus scan \
  --subscription "<subscription-id>" \
  --tenant       "<tenant-id>" \
  --output       all \
  --output-dir   ./argus-output \
  --drift \
  --evidence

# 5. Open the HTML report
open ./argus-output/argus_*.html        # macOS
xdg-open ./argus-output/argus_*.html    # Linux
```
</details>

<details>
<summary><b>🪟 Windows (PowerShell)</b></summary>

```powershell
# 1. Log in to Azure
az login

# 2. Pick the subscription you want to scan
az account set --subscription "<subscription-id>"

# 3. Grab the tenant and subscription IDs (reuse them in step 4)
az account show --query '{tenant: tenantId, sub: id}' -o table

# 4. Run a full scan
argus scan `
  --subscription "<subscription-id>" `
  --tenant       "<tenant-id>" `
  --output       all `
  --output-dir   .\argus-output `
  --drift `
  --evidence

# 5. Open the HTML report
Invoke-Item (Get-ChildItem .\argus-output\argus_*.html | Select-Object -First 1)
```
</details>

**What you'll see in the terminal:**

```
╔══════════════════════════════════════════════════════════════════╗
║                     ARGUS Scan Summary                           ║
╠══════════════════════════════════════════════════════════════════╣
║  Subscription:     prod-sub (00000000-0000-0000-0000-000000000000)║
║  Tenant:           Contoso                                        ║
║  Duration:         48s                                            ║
║                                                                   ║
║  Score:            42.8 / 100   Grade: D                          ║
║  Maturity:         Reactive                                       ║
║                                                                   ║
║  Findings:         87 (12 CRITICAL, 34 HIGH, 28 MED, 13 LOW)      ║
║  Attack chains:    6 (3 CRITICAL, 3 HIGH)                         ║
║  Top Quick Win:    Enable Defender for Servers (breaks 4 chains)  ║
║                                                                   ║
║  Reports written to ./argus-output                                ║
╚══════════════════════════════════════════════════════════════════╝
```

That's it. Open the HTML file to see the full blindspot analysis.

---

## Authentication

ARGUS uses Azure SDK's `DefaultAzureCredential`. It walks the auth chain in this order until one works:

1. **Environment variables** — `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`
2. **Workload identity** (if running in a Kubernetes pod with federated identity)
3. **Managed identity** (if running on an Azure VM, Function, Container)
4. **Azure CLI** — `az login` (the easiest path for laptops)
5. **Azure PowerShell** — `Connect-AzAccount`
6. **Visual Studio Code** auth
7. **Interactive browser** prompt

### Required Azure RBAC roles

| Role | Why ARGUS needs it |
|---|---|
| **Reader** | List resources via Resource Graph |
| **Security Reader** | Read Defender for Cloud findings, plans, secure score |

### Required Microsoft Graph permissions (for full Identity coverage)

A plain `az login` user account does **not** have these by default. Without them, several high-value Identity findings — including CHAIN-002 (App Registration takeover) — won't fire. ARGUS will print a loud warning at the top of the scan output if any Graph endpoint returned 403.

| Permission | What it unlocks |
|---|---|
| `Application.Read.All` | **Detect App Registrations with dangerous Graph permissions (CHAIN-002)** |
| `Directory.Read.All` | Enumerate users, groups, service principals |
| `Policy.Read.All` | Conditional Access policies, tenant settings |
| `RoleManagement.Read.Directory` | PIM eligible/active assignments |
| `AccessReview.Read.All` | Access reviews on guests and privileged accounts |
| `AuditLog.Read.All` | Drift analysis activity log queries |
| `IdentityRiskyUser.Read.All` | Risky user signals |
| `SecurityEvents.Read.All` | Defender alerts |

### One-shot SPN setup (recommended)

Instead of granting all 8 Graph permissions by hand, use the bundled setup script. It creates a Service Principal, assigns **Reader + Security Reader** on the subscription, grants all 8 Graph application permissions, requests admin consent, and prints a ready-to-export credential block.

**Who can run it:** you need to be a **Global Administrator** (or a Privileged Role Administrator) in the tenant, because the script requests admin consent for the Graph scopes. Run it once; after that everyone with the SPN credentials can scan.

**Prerequisites:** `az` CLI installed, `az login` completed as a Global Administrator, subscription ID + tenant ID handy.

<details open>
<summary><b>🍎 macOS / 🐧 Linux</b></summary>

```bash
# From the repo root (works if you built from source) or download the script first:
curl -LO https://raw.githubusercontent.com/vatsayanvivek/argus/main/scripts/setup-graph-permissions.sh
chmod +x setup-graph-permissions.sh

./setup-graph-permissions.sh <subscription-id> <tenant-id>
```
</details>

<details>
<summary><b>🪟 Windows (PowerShell)</b></summary>

```powershell
Invoke-WebRequest `
  -Uri "https://raw.githubusercontent.com/vatsayanvivek/argus/main/scripts/setup-graph-permissions.ps1" `
  -OutFile setup-graph-permissions.ps1

.\setup-graph-permissions.ps1 -SubscriptionId "<sub-id>" -TenantId "<tenant-id>"
```
</details>

**What the script prints at the end** — paste these into your shell so `argus` picks them up via environment variables:

<details open>
<summary><b>macOS / Linux</b></summary>

```bash
export AZURE_TENANT_ID="<printed-by-script>"
export AZURE_CLIENT_ID="<printed-by-script>"
export AZURE_CLIENT_SECRET="<printed-by-script>"

# Verify:
argus scan --subscription "<sub-id>" --tenant "$AZURE_TENANT_ID" --output html
# You should NOT see the yellow "LIMITED MICROSOFT GRAPH ACCESS" banner anymore.
```
</details>

<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
$env:AZURE_TENANT_ID     = "<printed-by-script>"
$env:AZURE_CLIENT_ID     = "<printed-by-script>"
$env:AZURE_CLIENT_SECRET = "<printed-by-script>"

argus scan --subscription "<sub-id>" --tenant $env:AZURE_TENANT_ID --output html
```
</details>

See [`scripts/README.md`](scripts/README.md) for the full script documentation, what each permission unlocks, and how to rotate the client secret when it expires.

**If you DON'T run the setup script:** `argus scan` still works — it just prints this warning at the top of the output and skips the identity-dependent rules:

```
⚠️  ═══════════════════════════════════════════════════════════
⚠️   LIMITED MICROSOFT GRAPH ACCESS
⚠️  ═══════════════════════════════════════════════════════════
⚠️   The scanning identity does not have full Microsoft Graph
⚠️   access. The following rules COULD NOT be evaluated:
⚠️     • zt_id_011 / cis_1_15  — App Registration high-priv perms
⚠️     • zt_id_003 / zt_id_007 — PIM analysis
⚠️     • zt_id_004 / zt_id_006 — Conditional Access policies
⚠️     • zt_id_010              — Access reviews
⚠️   This means CHAIN-002 (App Registration takeover) is NOT being checked.
⚠️  ═══════════════════════════════════════════════════════════
```

You can scan without Graph access and still get Resource-plane, Network, Workload, Data, and Visibility coverage.

---

## Examples

### Example 1 — Scan a single subscription (most common)

```bash
argus scan \
  --subscription 00000000-0000-0000-0000-000000000000 \
  --tenant       11111111-1111-1111-1111-111111111111 \
  --output       all \
  --output-dir   ./argus-output \
  --drift \
  --evidence
```

Produces:
- `argus-output/argus_<timestamp>.html` — self-contained HTML report (300–700 KB)
- `argus-output/argus_<timestamp>.json` — comprehensive JSON
- `argus-output/argus_<timestamp>.sarif` — SARIF 2.1.0 for GitHub / Azure DevOps
- `argus-output/argus-evidence-<timestamp>.zip` — compliance evidence bundle

### Example 2 — Just a score check (fast, quiet)

Useful for a quick health dashboard or a cron job:

```bash
argus score \
  --subscription 00000000-0000-0000-0000-000000000000 \
  --tenant       11111111-1111-1111-1111-111111111111
```

```
Score: 58.3 / 100   Grade: D   Maturity: Reactive
Findings: 62   Chains: 4   Trend: ↑ +6.2 vs last scan
```

### Example 3 — Scan every subscription in your tenant

Parallel scan of every Enabled subscription you have Reader access to. Output is a tenant rollup ranked worst-first.

```bash
argus scan \
  --org-wide \
  --tenant 11111111-1111-1111-1111-111111111111 \
  --output html
```

Restrict to one management group:

```bash
argus scan \
  --org-wide \
  --management-group "production-mg" \
  --tenant 11111111-1111-1111-1111-111111111111
```

### Example 4 — Permission drift standalone

Finds service principals and users with granted RBAC actions they never actually use. Great for least-privilege campaigns.

```bash
argus drift \
  --subscription 00000000-0000-0000-0000-000000000000 \
  --tenant       11111111-1111-1111-1111-111111111111 \
  --days         30
```

```
Permission Drift Analysis (112 identities, 30 days)

  IDENTITY                    TYPE              GRANTED  USED  UNUSED %  BLAST RADIUS
  prod-deploy-sp              ServicePrincipal  847      12    98.6%     CRITICAL
  legacy-monitoring-sp        ServicePrincipal  500      0     100.0%    CRITICAL
  ops-team-readonly           User              250      45    82.0%     CRITICAL

  High blast radius (60%+ unused): 87
```

### Example 5 — Continuous monitoring (daemon)

Runs a scan every 4 hours and fires Slack/Teams webhooks when the score drifts by more than 5 points:

```bash
argus monitor \
  --tenant       11111111-1111-1111-1111-111111111111 \
  --subscription 00000000-0000-0000-0000-000000000000 \
  --interval     4h \
  --config       ./argus.yaml \
  --webhook-on-drift
```

```
[2026-04-12T14:30:00Z] prod-sub: Score 72.5 → 68.3 (D-4.2) | +3 findings, -1 chain | next scan in 4h
```

### Example 6 — Use as a CI/CD quality gate

Exits with code **2** (distinct from `1` for errors) when thresholds are breached, so your pipeline fails loudly.

```bash
# Fail if ANY critical findings or chains exist
argus scan --subscription "$SUB" --tenant "$TENANT" --ci

# Fail if score drops below 60
argus scan --subscription "$SUB" --tenant "$TENANT" --ci --ci-min-score 60

# Fail only if 3+ CRITICAL findings
argus scan --subscription "$SUB" --tenant "$TENANT" --ci --ci-critical-threshold 3
```

GitHub Actions snippet:

```yaml
- name: ARGUS security gate
  run: |
    argus scan \
      --subscription ${{ secrets.AZURE_SUB }} \
      --tenant       ${{ secrets.AZURE_TENANT }} \
      --output       sarif \
      --ci --ci-min-score 60

- name: Upload SARIF to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ./argus-output/argus_latest.sarif
```

### Example 7 — Run as an HTTP API server

<details open>
<summary><b>Start the server (macOS / Linux)</b></summary>

```bash
export ARGUS_API_KEY="$(openssl rand -hex 32)"
argus server --port 8443 --workers 4 --auth-key "$ARGUS_API_KEY"
```
</details>

<details>
<summary><b>Start the server (Windows PowerShell)</b></summary>

```powershell
$env:ARGUS_API_KEY = -join ((48..57 + 97..102) | Get-Random -Count 64 | ForEach-Object { [char]$_ })
argus server --port 8443 --workers 4 --auth-key $env:ARGUS_API_KEY
```
</details>

<details open>
<summary><b>Submit a scan from another machine (curl — macOS / Linux / WSL / Git Bash)</b></summary>

```bash
curl -X POST https://argus-host:8443/api/v1/scan \
  -H "X-API-Key: $ARGUS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"subscription":"00000000-0000-0000-0000-000000000000","tenant":"11111111-1111-1111-1111-111111111111"}'

# {"scan_id":"abc123","status":"running"}

curl https://argus-host:8443/api/v1/scans/abc123 -H "X-API-Key: $ARGUS_API_KEY"
```
</details>

<details>
<summary><b>Submit a scan from another machine (PowerShell)</b></summary>

```powershell
$body = @{
  subscription = "00000000-0000-0000-0000-000000000000"
  tenant       = "11111111-1111-1111-1111-111111111111"
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -Uri "https://argus-host:8443/api/v1/scan" `
  -Headers @{ "X-API-Key" = $env:ARGUS_API_KEY } `
  -ContentType "application/json" `
  -Body $body

# Poll status:
Invoke-RestMethod `
  -Uri "https://argus-host:8443/api/v1/scans/abc123" `
  -Headers @{ "X-API-Key" = $env:ARGUS_API_KEY }
```
</details>

### Example 8 — List every loaded rule

Handy for SOC handbooks or compliance mapping docs:

```bash
argus rules list
```

### Example 9 — Suppress a finding with audit trail

```bash
argus suppress \
  --rule        "zt_vis_010" \
  --resource    "*" \
  --reason      "JIT VM access not GA in our region" \
  --approved-by "security@example.com" \
  --expires     "2026-12-31"
```

The suppression lands in `.argusignore`. Suppressed findings still appear in the report — with their justification — so auditors can review.

### Example 10 — Pre-deployment scan of a Terraform plan

Run the same 201 policies against a Terraform plan JSON **before** `terraform apply`. Details in [IaC pre-deployment scanning](#iac-pre-deployment-scanning).

<details open>
<summary><b>🍎 macOS / 🐧 Linux</b></summary>

```bash
terraform plan -out plan.out
terraform show -json plan.out > plan.json
argus iac plan.json --fail-on HIGH
```
</details>

<details>
<summary><b>🪟 Windows (PowerShell)</b></summary>

```powershell
terraform plan -out plan.out
terraform show -json plan.out | Out-File -Encoding utf8 plan.json
argus iac plan.json --fail-on HIGH
```
</details>

Exit code `0` = clean, `2` = gate tripped (CRITICAL or HIGH finding), `1` = tool error.

### Example 11 — View score trend

Every scan is recorded to `~/.argus/history/<subscription-id>/scans.jsonl`. To see the trend over the last 90 days:

```bash
argus trend --subscription 00000000-0000-0000-0000-000000000000 --days 90
```

```
ARGUS Score Trend (last 90 days, 5 scans)

  DATE                 SCORE  GRADE  FINDINGS  CHAINS  TREND
  2026-01-15 09:00:00  18.4   F      95        6       —
  2026-01-22 09:00:00  31.2   F      87        5       ↑ +12.8
  2026-01-29 09:00:00  47.8   D      71        4       ↑ +16.6
  2026-02-05 09:00:00  62.1   C      58        3       ↑ +14.3
  2026-02-12 09:00:00  78.4   B      42        1       ↑ +16.3

  Trajectory: 78.4 / 100 (improving by +60.0 points over 5 scans)
```

---

## IaC pre-deployment scanning

Catch misconfigurations in Terraform **before** `terraform apply` writes them to your tenant. The same 201 OPA/Rego policies that evaluate live Azure also evaluate a plan JSON, so a finding that would trip in production trips in CI instead.

### Workflow

```bash
# 1. Render your plan as JSON (terraform 1.x)
terraform plan -out plan.out
terraform show -json plan.out > plan.json

# 2. Scan it with ARGUS
argus iac plan.json
```

### Sample output

```
ARGUS IaC scan plan.json

→ 2 terraform resources evaluated
→ 30 findings (4 CRITICAL, 12 HIGH, 13 MEDIUM, 1 LOW)

CRITICAL
  CRITICAL  cis_3_3       azurerm_storage_account.data  Ensure public blob access is disabled on storage accounts
  CRITICAL  cis_8_1       azurerm_key_vault.prod        Ensure Key Vault has soft delete and purge protection enabled
  CRITICAL  zt_data_001   azurerm_storage_account.data  Storage account allows public blob access
  CRITICAL  zt_data_005   azurerm_key_vault.prod        Key Vault purge protection disabled

HIGH
  HIGH      cis_3_1       azurerm_storage_account.data  Ensure Secure transfer required is enabled
  HIGH      cis_3_4       azurerm_storage_account.data  Ensure default network access rule is Deny
  HIGH      zt_vis_001    azurerm_key_vault.prod        Security-relevant resource has no diagnostic settings
  …
```

Every finding names the terraform address (e.g. `module.prod.azurerm_storage_account.data`) so you can jump straight to the offending HCL block.

### Flags

| Flag | Default | Description |
|---|---|---|
| `--output` | `text` | `text`, `json`, or `sarif` |
| `--output-dir` | `./argus-output` | Where JSON / SARIF artifacts land |
| `--fail-on` | `HIGH` | Severity floor for exit-code-2: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE` |
| `--subscription` | pseudo | Cosmetic subscription ID in the report |
| `--tenant` | pseudo | Cosmetic tenant ID in the report |

### Supported resource types

The translator understands these `azurerm_*` types out of the box and maps them to ARM types so the full rule library fires against them:

- `storage_account`
- `key_vault`
- `mssql_server`, `sql_server`
- `postgresql_server`, `postgresql_flexible_server`
- `mysql_server`, `mysql_flexible_server`
- `cosmosdb_account`
- `kubernetes_cluster`
- `container_registry`
- `app_service`, `linux_web_app`, `windows_web_app`
- `function_app`, `linux_function_app`, `windows_function_app`
- `virtual_machine`, `linux_virtual_machine`, `windows_virtual_machine`
- `public_ip`
- `network_security_group`
- `virtual_network`, `subnet`

Unknown resource types are still carried through with their raw Terraform property names, so any IaC-native rule written against terraform idioms can still match them.

### Use in CI

```yaml
# GitHub Actions snippet
- name: Terraform plan
  run: |
    terraform plan -out plan.out
    terraform show -json plan.out > plan.json

- name: ARGUS IaC gate
  run: argus iac plan.json --fail-on HIGH --output sarif --output-dir ./argus-output

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ./argus-output/argus-iac.sarif
```

Exit code 2 stops the pipeline; SARIF annotations show up in the GitHub Security tab with the terraform address as the location.

---

## Graph-based chain discovery

The hand-authored chain library hits 51 specific patterns ("if finding X + Y + Z fire together, emit CHAIN-N"). The **pathfinder** is pattern-free — it builds a directed graph of every principal, scope, RBAC assignment, group membership, and managed-identity binding in your tenant, then walks it from weak entry points (guest users, no-MFA accounts, SPs whose credentials never expire) to high-value targets (key vaults, storage, databases, subscription root). Every walk it finds that exceeds the privilege threshold becomes a **DISC-N** attack chain alongside the hand-authored ones.

### Why it matters

A guest user with "Contributor on the sub" is a low-severity finding to every scanner. It becomes critical only when you look at the graph and see the subscription contains the production Key Vault. The pathfinder surfaces that walk automatically, with no rule author anywhere.

### How it runs

The pathfinder runs by default as part of `argus scan`. To disable it:

```bash
argus scan --discover-chains=false --subscription $SUB --tenant $TENANT
```

Every discovered chain is rendered in the same HTML / JSON / SARIF output as the hand-authored ones, but with a `DISC-` prefix and a narrative that traces the exact walk:

```
DISC-001  HIGH  external partner (guest) → prod subscription (3-hop RBAC walk)
Graph pathfinder discovered this walk: external partner (guest)
→ [role:Contributor] → prod → [contains] → rg1 → [contains] → kv-prod.
Entry weakness: Guest account; No MFA.

Priority fix: Remove Contributor role assignment on prod from
principal external partner (guest) (lower-privilege role or group-based
conditional assignment preferred).
```

### Weights

Role weights roughly capture attacker power:

| Role | Weight |
|---|---|
| Owner / User Access Administrator / RBAC Admin | 10 |
| Kubernetes Cluster Admin | 9 |
| Contributor / Key Vault Administrator / Storage Account Contributor | 7–8 |
| Network Contributor / VM Contributor | 6–7 |
| Reader / Monitoring Reader | 1 |
| (unknown) | 2 |

The default privilege threshold (`MinWeight=8`) drops walks made only of Reader assignments — they are noise, not chains.

### Current scope (MVP)

- Nodes: users (including guests), SPs, apps, managed identities, subscriptions, resource groups, resources, the `external:internet` root
- Edges: `has_role`, `member_of`, `is_credential_for`, `assigned_mi`, `contains`, `exposes_to`, `owns_app`
- Destinations: Key Vault, Storage, SQL, Postgres, MySQL, Cosmos DB, AKS, ACR, plus subscription root
- Algorithm: bounded BFS (max 6 hops) with dedupe by (source, destination, first role)

What is **not** yet covered:

- Entra directory role edges (Global Admin, Privileged Role Administrator) — only Azure RBAC is walked today
- Cross-tenant trust edges
- Transitive group membership (nested groups)
- OIDC federated-credential trust chains

---

## Command reference

Run `argus --help` for the full tree. Every subcommand supports `--help`.

| Command | Purpose |
|---|---|
| `argus scan` | Full pipeline: collect → evaluate 201 policies → correlate chains → score → report |
| `argus score` | Silent scan, prints score summary only |
| `argus rules list` | Show all 201 loaded rules grouped by source and pillar |
| `argus drift` | Permission drift analysis (granted vs. used RBAC actions) |
| `argus suppress` | Append a finding suppression to `.argusignore` with audit trail |
| `argus trend` | Show score history and delta for a subscription |
| `argus monitor` | Continuous monitoring daemon with webhook alerts |
| `argus server` | HTTP API daemon mode |
| `argus iac <plan.json>` | Pre-deployment scan of a Terraform plan |

### `argus scan` flags

| Flag | Default | Description |
|---|---|---|
| `--subscription <id>` | *(required unless --org-wide)* | Azure subscription ID |
| `--tenant <id>` | *(required)* | Azure tenant ID |
| `--compliance <filter>` | `all` | Frameworks: `cis-azure-2.0`, `nist-800-207`, `nist-800-53`, `all` |
| `--output <format>` | `all` | `html`, `json`, `sarif`, `all` |
| `--output-dir <path>` | `./argus-output` | Where to write reports |
| `--drift` | `false` | Also run permission drift analysis |
| `--evidence` | `false` | Also generate the compliance evidence zip |
| `--org-wide` | `false` | Discover and scan every Enabled subscription in the tenant |
| `--management-group <id>` | *(empty)* | Restrict `--org-wide` to subscriptions under this MG |
| `--suppress-file <path>` | `.argusignore` | Path to suppression YAML |
| `--show-suppressed` | `false` | Include suppressed findings (still annotated) |
| `--ci` | `false` | Enable CI/CD gate evaluation |
| `--ci-critical-threshold <n>` | `0` | Fail if CRITICAL findings ≥ N (0 = fail on any critical) |
| `--ci-chain-threshold <n>` | `0` | Fail if CRITICAL chains ≥ N |
| `--ci-min-score <n>` | `0` | Fail if score < N |
| `--discover-chains` | `true` | Run the graph pathfinder to surface DISC-* chains beyond the 51 hand-authored patterns |

### `argus monitor` flags

| Flag | Default | Description |
|---|---|---|
| `--tenant` | *(required)* | Azure tenant ID |
| `--subscription` | *(empty = all)* | Specific subscription, or all Enabled ones |
| `--interval` | `4h` | Time between scans (`30m`, `4h`, `24h`) |
| `--config` | *(empty)* | Path to `argus.yaml` for webhook settings |
| `--webhook-on-drift` | `false` | Fire webhooks when score changes by >5 points |

### `argus server` flags

| Flag | Default | Description |
|---|---|---|
| `--port` | `8443` | HTTP port |
| `--workers` | `4` | Max concurrent scans |
| `--auth-key` | *(empty = no auth)* | API key required in `X-API-Key` header |

API endpoints:

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/scan` | Submit a scan (returns scan ID) |
| `GET` | `/api/v1/scans/{id}` | Scan status + results |
| `GET` | `/api/v1/scans/{id}/report` | Full JSON report |
| `GET` | `/api/v1/rules` | List loaded policies |
| `GET` | `/api/v1/health` | Health check |

---

## CI/CD integration

Add `--ci` to any `argus scan` command to enable gate evaluation. ARGUS exits **2** when a threshold breaks — distinct from **1** for runtime errors — so CI can distinguish "unhealthy posture" from "tool broke".

```bash
# Example: fail only if 3+ CRITICAL findings
argus scan --subscription "$SUB" --tenant "$TENANT" --ci --ci-critical-threshold 3
```

Thresholds can also live in `argus.yaml` under `ci_gates:` — CLI flags always override.

---

## Configuration file

ARGUS reads a YAML config file for persistent settings. CLI flags always override.

Search order: explicit `--config` path → `./argus.yaml` → `~/.argus/config.yaml`.

```yaml
defaults:
  tenant_id: "your-tenant-id"
  compliance: "all"
  output: "all"
  output_dir: "./argus-output"
  drift: true

ci_gates:
  enabled: true
  fail_on_critical: true
  critical_threshold: 0
  high_chain_threshold: 5
  min_score: 50.0
  exit_code_on_fail: 2

webhooks:
  - name: "slack-security"
    url: "https://hooks.slack.com/services/..."
    format: "slack"
    events: ["on-complete", "on-critical"]

  - name: "teams-ops"
    url: "https://outlook.office.com/webhook/..."
    format: "teams"
    events: ["on-critical"]

api_server:
  port: 8443
  workers: 4
  auth_key: "${ARGUS_API_KEY}"
```

`${VAR_NAME}` expressions are expanded from environment variables at load time.

---

## Webhooks

ARGUS can POST scan results to HTTP endpoints in three formats:

| Format | Payload | Use case |
|---|---|---|
| `json` | Full scan summary | Custom dashboards, SIEM integration |
| `slack` | Slack Block Kit message | Security team Slack channel |
| `teams` | Microsoft Teams MessageCard | Ops team Teams channel |

Events:

- `on-complete` — every scan
- `on-critical` — only when CRITICAL findings exist
- `on-chain` — only when chains are detected

---

## Output formats

A single `--output all` produces:

| File | Format | Audience | Size (typical) |
|---|---|---|---|
| `argus_<timestamp>.html` | Self-contained HTML | Security team, leadership | 300–700 KB |
| `argus_<timestamp>.json` | Comprehensive JSON | Pipelines, dashboards | 150–300 KB |
| `argus_<timestamp>.sarif` | SARIF 2.1.0 | GitHub Security tab, IDEs | 100–200 KB |
| `argus-evidence-<timestamp>.zip` | Compliance bundle | Auditors (SOC 2, ISO 27001) | 30–80 KB |

### HTML report contents

A modern, consulting-grade single file with no CDN calls or external resources:

1. Cover page — gradient header, large grade letter (A–F), score, maturity level
2. Microsoft Graph warning banner (if Graph scopes were missing)
3. Trend banner — score delta vs previous scan
4. **Your Blindspots** executive summary
5. **Top 5 Quick Wins** — Pareto remediation table
6. **Attack Chains** — every detected chain with personalized narrative
7. Zero Trust pillar breakdown and NIST 800-207 tenet heatmap
8. Findings table (sortable, no JS libraries)
9. Permission drift analysis (if `--drift` was set)
10. Remediation roadmap — Terraform + `az` CLI snippets with real resource names
11. Compliance mapping — NIST 800-53, NIST 800-207, MITRE ATT&CK
12. Collapsible raw-JSON technical appendix

### Evidence bundle contents

```
argus-evidence-<timestamp>.zip
├── executive_summary.json
├── zt_score_report.json
├── attack_chains.json
├── cis_azure_compliance.csv
├── nist_800_53_mapping.csv
├── nist_800_207_assessment.csv
├── remediation_plan.md
├── drift_report.csv            # if --drift was set
└── raw_findings.json
```

This is the bundle you hand an auditor for a SOC 2 / ISO 27001 / NIST 800-207 evidence package.

---

## The 51 attack chains

ARGUS correlates findings into 51 distinct attack chain patterns. Each chain has:

- A unique ID (`CHAIN-001` through `CHAIN-051`)
- Severity (CRITICAL / HIGH)
- A narrative personalized with **your** resource names, user counts, and Defender plan list
- 3–6 attack steps with actor, action, MITRE technique, and enabling rule
- Blast-radius breakdown (initial access, lateral movement, max privilege, data at risk, scope %)
- Regulatory impact entries (PCI DSS, GDPR, ISO 27001, SOC 2, HIPAA, NIST 800-53)
- A `MinimalFixSet` — the smallest set of rules that, if fixed, breaks the chain
- A `PriorityFix` recommendation and `BreakingNote` explaining how each fix reduces likelihood

Selected chains:

| ID | Title | Severity |
|---|---|---|
| **CHAIN-001** | Internet-exposed VM to subscription takeover | CRITICAL |
| **CHAIN-002** | App Registration Graph abuse to tenant data | CRITICAL |
| **CHAIN-003** | Legacy auth bypass to privileged takeover | CRITICAL |
| **CHAIN-005** | Public storage + no diagnostics = silent exfiltration | CRITICAL |
| **CHAIN-006** | AKS public endpoint + privileged containers = cluster takeover | CRITICAL |
| **CHAIN-008** | Defender disabled + open ports = blind execution | CRITICAL |
| **CHAIN-009** | Key Vault no protection + no alerts = ransomware | CRITICAL |
| **CHAIN-010** | No private endpoint + SQL allows all IPs + no audit = DB breach | CRITICAL |
| **CHAIN-019** | Permanent privileged + no PIM + no reviews = insider threat | CRITICAL |
| **CHAIN-020** | No Sentinel + no diagnostics + low retention = invisible persistence | CRITICAL |
| **CHAIN-022** | Emergency access lockout to tenant takeover | CRITICAL |
| **CHAIN-025** | AKS cluster full compromise | CRITICAL |
| **CHAIN-028** | Key Vault silent breach and purge | CRITICAL |
| **CHAIN-030** | Storage account ransomware with no recovery | CRITICAL |
| **CHAIN-044** | Admin credential spray to irrecoverable tenant lock | CRITICAL |
| **CHAIN-048** | Cosmos DB to cross-service data theft | CRITICAL |
| **CHAIN-049** | AKS full stack compromise — registry to node | CRITICAL |
| **CHAIN-051** | Token replay to persistent backdoor | CRITICAL |

Full 51 patterns and trigger logic live in `internal/engine/correlator.go`.

### Why CHAIN-002 matters

Most scanners look at an App Registration holding `Application.ReadWrite.All`, rate it a "medium", and move on. ARGUS sees it as **part of a chain**: a tenant-wide Graph-permissioned App Registration, plus storage accounts open to any network, plus App Services accepting legacy auth, equals a **3-hop path from one phished developer to production customer data**. None of them light up red on Defender for Cloud individually. Together they are a tenant-takeover.

---

## The 201 rules

### CIS Microsoft Azure Foundations Benchmark v2.0 — 92 rules

| Section | Domain | Rules |
|---|---|---|
| 1 | Identity and Access Management | 17 |
| 2 | Microsoft Defender for Cloud | 15 |
| 3 | Storage Accounts | 10 |
| 4 | Database Services | 7 |
| 5 | Logging and Monitoring | 9 |
| 6 | Networking | 11 |
| 7 | Virtual Machines | 7 |
| 8 | Key Vault | 7 |
| 9 | App Service | 9 |

Every CIS rule maps to NIST 800-53 control(s), the NIST 800-207 ZT tenet, a Terraform remediation snippet, and an `az` CLI remediation command.

### Custom Zero Trust rules — 109 rules

Mapped to the 5 NIST SP 800-207 pillars:

| Pillar | Rules | Examples |
|---|---|---|
| **Identity** | 26 | SP credentials never expire, no PIM, dangerous Graph perms, no break-glass, no auth strength, no sign-in/user risk, MFA not enforced, no access reviews |
| **Network** | 20 | NSG SSH/RDP from 0.0.0.0/0, subnet without NSG, no Firewall / WAF / DDoS, VPN downgrade, VNet peering forwarded traffic |
| **Workload** | 24 | AKS public API, no network policy, no Azure RBAC, no pod security, ACR admin / public, remote debug, no managed identity, no disk encryption |
| **Data** | 20 | Public blob, Cosmos DB all networks, no TDE, no auditing, no purge protection, no soft delete, no versioning, no backup, Event Hub no CMK |
| **Visibility** | 20 | No Log Analytics, no diagnostic settings, Defender Free tier, no alert rules, no action groups, NSG flow log short retention |

Each rule carries a `chain_role`:

| Role | Meaning |
|---|---|
| **ANCHOR** | Gives the attacker initial access. Without an anchor, no chain starts. |
| **AMPLIFIER** | Escalates what an anchor enables. Widens blast radius. |
| **ENABLER** | Removes a defense (visibility, alerting). Doesn't grant access on its own. |

Run `argus rules list` to see the full table.

---

## Suppressions (`.argusignore`)

Every security tool needs a way to mark findings "accepted risk" without losing the audit trail. ARGUS uses a YAML file named `.argusignore` (like `.gitignore`) at the root of your working directory.

Example:

```yaml
suppressions:
  # Suppress one rule on one specific resource
  - rule_id: "zt_net_010"
    resource_id: "/subscriptions/.../storageAccounts/legacy-tfstate"
    reason: "Legacy storage account — migration scheduled Q2 2026"
    approved_by: "security@example.com"
    expires: "2026-06-30"
    created_at: "2026-04-11"

  # Suppress a rule everywhere (accepted risk)
  - rule_id: "zt_vis_010"
    resource_id: "*"
    reason: "JIT VM access not yet GA in our region"
    approved_by: "ciso@example.com"
    expires: "2026-12-31"
    created_at: "2026-04-11"

  # Wildcard suffix — suppress for every storage account ending in -tfstate
  - rule_id: "cis_3_4"
    resource_id: "*-tfstate"
    reason: "Terraform state buckets need broad network access for CI/CD"
    approved_by: "platform@example.com"
    expires: "2026-12-31"
    created_at: "2026-04-11"
```

Suppressed findings are **not** silently dropped — they appear in the report's "Suppressed Findings" section with reason, approver, and expiry, so reviewers can challenge accepted-risk decisions during audits.

Append entries via `argus suppress` (validates the rule ID, refuses past expiry dates, and prompts for confirmation).

ARGUS warns at scan time if a suppression is **expired** or **expiring within 30 days**.

See `.argusignore.example` for a starter template.

---

## Architecture

ARGUS is built around 6 design principles:

### 1. Universal collector — zero per-service Go code

Azure Resource Graph handles ALL resource collection via a single KQL query. One query returns every resource type in the subscription regardless of service. New Azure services are automatically covered.

### 2. Complete segregation — data, logic, orchestration

| Layer | Files | Contents |
|---|---|---|
| **Data** | `data/benchmarks/*.csv`, `data/remediation/*.csv` | CIS rules, NIST controls, MITRE techniques, remediation snippets |
| **Logic** | `policies/azure/cis/*.rego`, `policies/azure/zt/*.rego` | Every check is an OPA/Rego policy |
| **Orchestration** | `internal/**/*.go` | Collectors, engine, scorer, reporters |

Adding a new rule = one Rego file + one CSV row. **Zero Go changes required.**

### 3. OPA/Rego is the rule engine — not Go if/else

Every check lives in a `.rego` file in `policies/`. Go feeds JSON to OPA, OPA evaluates all policies, Go maps violations to findings using CSV metadata. **Go never contains rule evaluation logic.**

### 4. Enterprise output quality

Every finding carries the exact resource ID, plain-English business impact, the specific attack scenario it enables, which chains it participates in, blast radius, compliance framework mapping, Terraform fix, and `az` CLI fix.

### 5. Works on any subscription in any state

No prerequisites. No required services. The tool always completes:
- Defender Free tier → `zt_vis_003` fires
- Diagnostics off → `zt_vis_001` fires
- Sentinel missing → `zt_vis_007` fires
- No Conditional Access policies → `zt_id_006` fires

Disabled services are findings, not blockers.

### 6. Attack chains are the product — not the finding list

Individual findings are inputs to the chain engine. Attack chains are the primary output. Every report leads with chains before findings.

---

## Build from source

Requires **Go 1.22 or later**. The Makefile handles the embed-prep step (mirroring `policies/` and `data/` into package directories that own the `//go:embed` directives).

```bash
git clone https://github.com/vatsayanvivek/argus.git
cd argus

# Build for your current platform
make build

# Build for all 5 platforms (linux, mac-intel, mac-arm, windows)
make build-all

# Run tests
make test

# Run tests with race detector
go test ./... -race -timeout 180s

# Run tests with coverage report
make test-coverage
```

**Reminder:** the [LICENSE](LICENSE) prohibits modification, forking, and redistribution of modified versions. You may build from source for personal or internal use.

---

## Troubleshooting

### Generic (all platforms)

| Symptom | Likely cause | Fix |
|---|---|---|
| `DefaultAzureCredential: failed to acquire token` | Not logged in | Run `az login` (or export `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET`) |
| `AuthorizationFailed` on Resource Graph | Missing Reader role on the subscription | Ask your Azure admin for **Reader** |
| Yellow Graph warning banner in HTML | Missing Graph scopes | Run the [SPN setup script](#one-shot-spn-setup-recommended) |
| `403` on Defender calls | Missing Security Reader | Ask your Azure admin for **Security Reader** |
| Scan takes > 3 minutes | Large subscription or `--org-wide` | Normal — enumeration scales with resource count |
| HTML report won't open from command line | Path escaping / stale timestamp | Use `Get-ChildItem` (Windows) / `ls -t` (Unix) to find the newest file and open with `Invoke-Item` / `open` / `xdg-open` |
| `--org-wide` only scans one subscription | No Reader on the others | Grant Reader at the management-group level |
| `argus` command not found after install | Binary not on `PATH` | Confirm `/usr/local/bin` (Unix) or `%USERPROFILE%\bin` (Windows) is on `PATH`; open a new shell |
| Windows: "Windows protected your PC" SmartScreen | Unsigned binary | Click **More info → Run anyway**, or `Unblock-File` in PowerShell |
| macOS: "argus cannot be opened because it is from an unidentified developer" | Gatekeeper quarantine | `xattr -d com.apple.quarantine $(which argus)` |

### Platform-specific

<details>
<summary><b>🪟 Windows — common PowerShell pitfalls</b></summary>

- **Backslashes vs. forward slashes**: ARGUS paths work with either — `./argus-output/argus_*.html` and `.\argus-output\argus_*.html` are both valid.
- **Line continuation**: use backtick `` ` `` not backslash `\` in PowerShell. Every multi-line command in this README has a PowerShell variant.
- **Execution policy blocks `.ps1`**: if `setup-graph-permissions.ps1` refuses to run, loosen policy for this shell only:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  ```
</details>

<details>
<summary><b>🍎 macOS — Apple Silicon Rosetta confusion</b></summary>

If you accidentally downloaded `argus-darwin-amd64` on an M-series Mac, you'll get a "bad CPU type in executable" or a silently slow binary running under Rosetta 2. Re-download `argus-darwin-arm64` and overwrite.
</details>

<details>
<summary><b>🐧 Linux — glibc version mismatch on old distros</b></summary>

The binaries are built as CGO-disabled static Go binaries, so they should run on any modern distro. If you see a dynamic linker error on a pre-2018 distro, build from source:

```bash
git clone https://github.com/vatsayanvivek/argus.git && cd argus && make build
```
</details>

---

## License

ARGUS is published under the **PolyForm Strict License 1.0.0** — a source-available license that permits running and reading the source but prohibits modification, forking, and redistribution.

- Full text: [LICENSE](LICENSE)
- Canonical: [polyformproject.org/licenses/strict/1.0.0](https://polyformproject.org/licenses/strict/1.0.0)

This is a deliberate choice to keep the rule library, attack-chain definitions, and output schema consistent across every install.

At a glance:

| ✅ You may | ❌ You may not |
|---|---|
| Run ARGUS against your own Azure environment | Modify the source code |
| Read every line of source to audit it | Fork and publish your own version |
| Use generated reports in your compliance docs | Embed the source into another product |
| File bug reports and feature requests | Sell ARGUS or charge for hosted access |

---

## Links

| Channel | Where |
|---|---|
| 🐛 **Bug reports** | [github.com/vatsayanvivek/argus/issues](https://github.com/vatsayanvivek/argus/issues) |
| 🔒 **Security advisories** | [github.com/vatsayanvivek/argus/security/advisories](https://github.com/vatsayanvivek/argus/security/advisories) |
| 📦 **Releases** | [github.com/vatsayanvivek/argus/releases](https://github.com/vatsayanvivek/argus/releases) |

---

> **Source-available · Run it on your own subscription · No agent, no SaaS, no data leaves your machine.**
