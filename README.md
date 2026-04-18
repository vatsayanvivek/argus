<div align="center">

```
 █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
███████║██████╔╝██║  ███╗██║   ██║███████╗
██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
```

### **Attack chain analysis for Microsoft Azure**

*Find the exact attacker path that chains your misconfigurations together — before anyone else does.*

[![Release](https://img.shields.io/github/v/release/vatsayanvivek/argus?color=blue)](https://github.com/vatsayanvivek/argus/releases/latest)
[![License](https://img.shields.io/badge/license-PolyForm%20Strict%201.0.0-blue)](LICENSE)
[![Go](https://img.shields.io/badge/built%20with-Go%201.25-00ADD8)](https://golang.org)
[![Policies](https://img.shields.io/badge/policies-OPA%20%2F%20Rego-7B2D8E)](https://www.openpolicyagent.org)
[![SLSA Level 3](https://img.shields.io/badge/SLSA-Level%203-brightgreen)](https://github.com/vatsayanvivek/argus/attestations)
[![SBOM](https://img.shields.io/badge/SBOM-SPDX%202.3-green)](https://github.com/vatsayanvivek/argus/releases/latest)
[![Cosign Signed](https://img.shields.io/badge/cosign-signed-success)](https://search.sigstore.dev/)
[![Docker](https://img.shields.io/badge/ghcr.io-argus-2496ED)](https://ghcr.io/vatsayanvivek/argus)
[![Trivy CVEs](https://img.shields.io/badge/trivy-0%20HIGH%2F0%20CRITICAL-brightgreen)](https://github.com/vatsayanvivek/argus/security/code-scanning)

</div>

---

## What ARGUS does in one paragraph

Most Azure security scanners produce a flat list of 200 findings and leave you wondering which ones actually matter. ARGUS reads your full Azure Resource Graph, Entra identity surface, RBAC graph, PIM schedules, and network topology — then **correlates individual misconfigurations into named attack chains a real adversary would exploit**. Instead of "Storage has public blob access + User has no MFA + Key Vault has network rule Allow", you see **CHAIN-019: guest user → stolen session → Key Vault key read → database exfiltration, and the single rule to change that breaks the chain.**

245 policies. **200 attack chains** (51 hand-authored + 149 data-driven across Identity, Data, Network, Workload, AI/ML, Integration, Backup, Visibility, DevOps). A graph pathfinder that discovers chains nobody wrote down. IaC pre-deployment scanning across Terraform, ARM, Bicep, and ARM what-if. Four compliance packs (SOC 2, HIPAA, PCI DSS 4.0, ISO 27001:2022) with 100% rule-to-control coverage. A local-only dashboard (`argus serve`). A VSCode extension for inline IaC findings. Zero telemetry, no SaaS, no data ever leaves your laptop.

---

## 🎯 At a glance

| | |
|---|---|
| **245 policies** | 91 CIS Azure 2.0 + 154 Zero Trust native rules (identity, data, network, visibility, workload, AI/ML, integration, backup) |
| **200 attack chains** | 51 hand-authored with full narratives + 149 data-driven across every pillar |
| **`argus serve`** | Local-only dashboard — findings, attack graph viz, compliance, drift, scan history |
| **`argus explain`** | Terminal-native rule and chain documentation |
| **`argus diff`** | Scan-to-scan drift diff (added / resolved findings and chains) |
| **`argus scan --resume`** | Resume a throttled / interrupted scan from its checkpoint |
| **`argus scan --activity-log-days`** | Configurable Activity Log window (default 30, max 90) |
| **`argus grant-permissions`** | Built-in service-principal bootstrap — no separate script download |
| **Attack graph in HTML reports** | Every report embeds an interactive SVG attack graph |
| **VSCode extension** | Inline IaC findings as you write Bicep / Terraform / ARM |
| **Graph pathfinder** | Nested groups + Entra directory roles + PIM Eligible/Active + cross-subscription + NSG-derived exposure edges |
| **245 Terraform types** | azurerm_* resource coverage — more than Checkov |
| **4 IaC formats** | Terraform plan, ARM template, Bicep-compiled JSON, ARM what-if |
| **Full ARM expression interpreter** | 40+ pure functions evaluated at scan time |
| **4 compliance packs** | SOC 2, HIPAA, PCI DSS 4.0, ISO 27001:2022 — 100% rule-to-control mapped |
| **Multi-platform** | macOS (amd64/arm64), Linux (amd64/arm64), Windows (amd64) |
| **Docker image** | ~25 MB on a hardened Chainguard base with zero known CVEs |
| **Supply-chain hardened** | SLSA build-provenance + SBOMs + cosign-signed image + Trivy CVE scan on every release |

---

## 🚀 Install in 30 seconds

### Windows (GUI installer — recommended)
Download **`argus-setup.exe`** from the [latest release](https://github.com/vatsayanvivek/argus/releases/latest) and double-click. Standard Windows wizard (Next → Next → Finish). No admin required.

### Windows (PowerShell, no GUI)
```powershell
# Download the raw exe from the latest release page, then:
.\argus-windows-amd64.exe install
# Open a new PowerShell:
argus --version
```

### macOS (Apple Silicon)
```bash
curl -LO https://github.com/vatsayanvivek/argus/releases/latest/download/argus-darwin-arm64
chmod +x argus-darwin-arm64 && ./argus-darwin-arm64 install
# Open a new terminal:
argus --version
```

### macOS (Intel) / Linux
```bash
# Replace <platform> with darwin-amd64, linux-amd64, or linux-arm64:
curl -LO https://github.com/vatsayanvivek/argus/releases/latest/download/argus-<platform>
chmod +x argus-<platform> && ./argus-<platform> install
```

### Docker (runs anywhere, zero install on host, no SmartScreen/Defender friction)

**Full scan command — outputs land in `./argus-output/` on your host:**

```bash
# macOS / Linux
mkdir -p argus-output
docker run --rm \
  -v "$HOME/.azure:/home/nonroot/.azure:ro" \
  -v "$(pwd)/argus-output:/home/nonroot/argus-output" \
  ghcr.io/vatsayanvivek/argus:latest \
  scan \
    --tenant <tenant-id> \
    --subscription <subscription-id> \
    --output-dir /home/nonroot/argus-output

# Windows PowerShell
New-Item -ItemType Directory -Force -Path argus-output | Out-Null
docker run --rm `
  -v "${HOME}\.azure:/home/nonroot/.azure:ro" `
  -v "${PWD}\argus-output:/home/nonroot/argus-output" `
  ghcr.io/vatsayanvivek/argus:latest `
  scan `
    --tenant <tenant-id> `
    --subscription <subscription-id> `
    --output-dir /home/nonroot/argus-output
```

Reports (`*.html`, `*.json`, `*.sarif`) land in the `argus-output/` folder next to your terminal's working directory. Open the HTML in a browser.

**Auth options**:
- **Easiest**: run `az login` on the host first; the `~/.azure` volume mount hands credentials to the container
- **Service principal** (CI / non-interactive): pass env vars `-e AZURE_TENANT_ID -e AZURE_CLIENT_ID -e AZURE_CLIENT_SECRET`
- **Managed Identity** (when the host is an Azure VM): identity flows automatically; no volume mount needed

**Why Docker sidesteps every Windows install friction**:
- No SmartScreen "Unknown publisher" warning (the image is signed with cosign via GitHub OIDC)
- No Windows Defender scanning of the exe (container is sandboxed)
- No PATH setup
- Identical behaviour on Windows / macOS / Linux / any CI runner

### Package managers (once we publish taps — coming soon)

```bash
# macOS / Linux via Homebrew tap
brew tap vatsayanvivek/argus https://github.com/vatsayanvivek/argus
brew install argus

# Windows via Scoop
scoop bucket add vatsayanvivek https://github.com/vatsayanvivek/argus
scoop install argus

# Windows via winget
winget install VatsayanVivek.Argus
```

Manifests live in [`scripts/package-managers/`](scripts/package-managers/) and are regenerated per release by `scripts/package-managers/update-manifests.sh`.

### VSCode extension

Install the **ARGUS IaC Scanner** from the marketplace (or build locally from [`vscode-extension/`](vscode-extension/)). On save, inline diagnostics appear in your `.bicep`, `.tf`, and ARM template JSON files — the extension shells out to your local `argus` binary, so **nothing leaves your machine**.

---

## ⬆️ Updating to a new release

`argus update` is a **self-updater** baked into the binary. It pulls the requested release from GitHub, verifies its SHA-256, and atomically swaps the running exe in place — no admin, no reinstall, works on every platform.

### Update to the latest release

```bash
argus update
```

Example output:
```
Current version : v1.0.0
Latest release  : v1.1.1
Platform        : darwin/arm64
Downloading https://github.com/vatsayanvivek/argus/releases/download/v1.1.1/argus-darwin-arm64 ...
SHA-256 verified against SHA256SUMS.
Replaced /Users/alice/.local/bin/argus with v1.1.1.
Run: argus --version
```

### Pin to a specific version (downgrade or lock)

```bash
argus update --version v1.0.0         # downgrade / pin
argus update --version v1.1.1 --force # re-install the current version (recover from corruption)
```

### Check what's available without installing

```bash
argus update --check   # prints the latest tag and exits
argus update --list    # lists every release version available on GitHub
```

### From Docker

Docker users update by pulling the new tag:

```bash
docker pull ghcr.io/vatsayanvivek/argus:latest     # always-latest
docker pull ghcr.io/vatsayanvivek/argus:v1.1.1     # pin to a specific version
```

### From a package manager

```bash
brew upgrade argus          # Homebrew
scoop update argus          # Scoop
winget upgrade VatsayanVivek.Argus
```

### "I installed v1.0.0 months ago, now v1.1.1 is out — how do I jump?"

Just run `argus update`. It auto-detects your current version, fetches the newest release, SHA-256-verifies it, and does an atomic swap of the running binary. **All local configuration (`.argusignore`, output dirs, scan history) stays intact** — the updater only replaces the executable.

If you want to see what changed between your version and the latest before upgrading, visit the [releases page](https://github.com/vatsayanvivek/argus/releases) — every release has a change summary and the SHA-256 checksums of every artifact.

---

## 🔐 Trust & verification — every URL, every artifact

*A security tool is only as trustworthy as its supply chain. Every ARGUS release comes with a full stack of cryptographic attestations, all free and publicly verifiable. Nothing is hidden.*

| Trust artifact | Where to find it | What it proves | How to verify |
|---|---|---|---|
| **GitHub release page** | https://github.com/vatsayanvivek/argus/releases/latest | Canonical download location for every platform binary, installer, SBOM, and checksum file | Visit URL, inspect assets |
| **SHA-256 checksums** | https://github.com/vatsayanvivek/argus/releases/latest/download/SHA256SUMS | Cryptographic fingerprint of every binary in the release | `sha256sum -c SHA256SUMS` |
| **Per-binary SBOMs (SPDX 2.3)** | `argus-<platform>.sbom.spdx.json` — one per platform in the release assets | Full inventory of every Go module compiled into each binary | `grype sbom:argus-linux-amd64.sbom.spdx.json` or `trivy sbom argus-linux-amd64.sbom.spdx.json` |
| **SLSA build-provenance attestation** | https://github.com/vatsayanvivek/argus/attestations | Cryptographic proof that each binary was built from a specific commit on GitHub-hosted runners — signed via Sigstore, no private keys | `gh attestation verify argus-linux-amd64 --owner vatsayanvivek` |
| **Sigstore transparency log** | https://search.sigstore.dev/ — search by image name or commit SHA | Public, append-only log of every signature event. Nothing signed with ARGUS's identity can ever be hidden or retroactively removed. | Search for `vatsayanvivek/argus` to see every attestation |
| **Docker image** | https://ghcr.io/vatsayanvivek/argus — clean registry, only `:<version>` and `:latest` tags | The container image distributed via GHCR | `docker pull ghcr.io/vatsayanvivek/argus:latest` |
| **Docker image cosign signature** | Stored in GHCR alongside the image, as `:sha256-<digest>.sig` references | The image was signed by the ARGUS release workflow using GitHub's OIDC identity | See verification command below |
| **Trivy CVE scan report** | https://github.com/vatsayanvivek/argus/security/code-scanning | Zero HIGH/CRITICAL CVEs — the release workflow fails if any are present | Browse GitHub Security tab (free for public repos; if the page is empty, enable "Default setup" at repo Settings → Code security) |
| **Chainguard hardened base image** | `cgr.dev/chainguard/static:latest` — [image catalog](https://images.chainguard.dev/directory/image/static/versions) | Base layer of the ARGUS Docker image is itself zero-CVE, rebuilt within hours of every upstream fix | `trivy image cgr.dev/chainguard/static:latest` |
| **MAINTAINERS branching model** | [MAINTAINERS.md](MAINTAINERS.md) | Every release gets a permanent `release/vX.Y.Z` branch frozen at the release commit, so users can browse any old version's exact source | `git checkout release/v1.0.0` |

### How a customer verifies the full chain

```bash
# 1. Docker image signature (cosign, keyless)
cosign verify ghcr.io/vatsayanvivek/argus:v1.0.0 \
  --certificate-identity-regexp='^https://github\.com/vatsayanvivek/argus/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com

# 2. Binary SLSA attestation (GitHub-native)
gh attestation verify argus-linux-amd64 --owner vatsayanvivek

# 3. SHA-256 integrity (downloaded alongside binaries)
cd ~/Downloads && sha256sum -c SHA256SUMS

# 4. SBOM parses + scans clean
grype sbom:./argus-linux-amd64.sbom.spdx.json

# 5. Docker image CVE scan
trivy image ghcr.io/vatsayanvivek/argus:latest
```

If any of these fail, the binary you have isn't the one we published. No ambiguity.

---

## 🎬 Features — the full list

### Attack-chain analysis (what makes ARGUS different)

- **200 attack chains** — 51 hand-authored Go builders with full narratives + 149 data-driven JSON specs across Identity / Data / Network / Workload / AI/ML / Integration / Backup / Visibility / DevOps
- **Graph-based pathfinder** auto-discovers chains nobody wrote down:
  - **Nested group walks**: user → inner group → outer group → role assignment → scope (the #1 way Owner access hides in real environments)
  - **Entra directory roles**: Global Admin / Privileged Role Admin / Application Admin at tenant root, recognised with tenant-takeover weight 10
  - **PIM Eligible + Active**: PIM assignments become graph edges with an activation-step confidence penalty
  - **Cross-subscription edges**: when scanning org-wide, a user with Owner on sub A and UAA on sub B surfaces as a combined-reach chain
  - **NSG-derived exposure**: NSG inbound Allow-from-internet rules produce weighted exposes_to edges to VMs, AKS, App Services
  - **Calibration regression**: 4 canonical attacker patterns tested in CI guarantee weight changes never silently drop a real chain
- **Minimal-fix recommendation**: break the most chains with the fewest changes — pareto-ranked by blast radius

### Rules engine

- **245 policies** (91 CIS Azure 2.0 + 154 ARGUS Zero Trust)
- **OPA / Rego**: every rule is auditable, versioned, testable
- **Coverage across Azure**: Identity/IAM, Storage, Databases (SQL, PostgreSQL, MySQL, Cosmos, Synapse, Redis), Networking (VNet, NSG, Firewall, App Gateway, Bastion, Private DNS, VPN Gateway), Compute (VM, VMSS, AKS, Container Apps), Data/Analytics (Data Factory, Databricks, Synapse), AI/ML (Cognitive Services, Azure OpenAI, ML Workspace), Integration (API Management, Logic Apps, Event Grid, Service Bus, Event Hub), Backup/DR (Recovery Services Vault), DevOps (App Configuration), Observability (Log Analytics, Activity Log)
- **MITRE ATT&CK for Cloud** technique tagging on every finding
- **CIS benchmark + NIST 800-53 + NIST 800-207** control mapping inline on every rule

### IaC pre-deployment scanning

- **4 input formats**, auto-detected from the JSON envelope:
  - Terraform plan JSON (`terraform show -json plan.out`)
  - ARM deployment template JSON
  - Bicep-compiled JSON (`bicep build`)
  - ARM what-if output (`az deployment group what-if --output json`)
- **Full ARM expression interpreter**: 40+ pure functions (`parameters`, `variables`, `concat`, `format`, `if`, `resourceId`, `length`, `substring`, arithmetic, array helpers, base64, JSON, ...) evaluated at scan time so `"name": "[concat('kv-', parameters('env'))]"` resolves correctly
- **245 azurerm_* resource types** dispatched (more than Checkov's ~150)
- **Opaque markers** for runtime-only ARM functions (`reference`, `listKeys`, `environment`) so rules neither confirm nor deny predicates that can't be statically resolved

### Compliance packs

- **SOC 2** (AICPA TSP 100, 2017 revised 2022)
- **HIPAA Security Rule** (45 CFR Part 164 Subpart C — Technical + Administrative safeguards)
- **PCI DSS 4.0** (PCI SSC, Req 1–11 excluding physical)
- **ISO/IEC 27001:2022** (Annex A organisational + technological controls)
- **100% rule-to-control coverage**: every one of the 245 rules cites at least one control in each of the 4 frameworks
- **Per-framework coverage report** in the JSON output: total controls, covered controls, coverage %, per-control fired rules, worst severity observed
- **Findings decorated** with the specific control IDs they satisfy — auditor-ready

### CLI UX

- **Live multi-line scan progress**: per-collector table (resources / identity / RBAC / defender / activity / policy) with state + elapsed time + running count
- **Preflight connectivity check**: 5s-per-endpoint probe of Azure endpoints before the scan starts; fails fast with a diagnostic instead of a 60s hang on blocked networks
- **Branded banner** with cyan→magenta gradient (respects NO_COLOR and non-TTY)
- **`argus install`**: self-installer that copies the binary to a standard location and adds it to PATH (no admin required)
- **`argus update`**: self-upgrade with SHA-256 verification and atomic binary swap (Windows rename trick for in-place upgrade of a running exe)
- **`argus check-permissions`**: preflight probe of Microsoft Graph + ARM scopes available to the scanning identity — know before the scan starts whether PIM, CA, Access Reviews, and directory roles will be visible
- **Multiple output formats**: human terminal, HTML report, JSON, SARIF (for GitHub Security tab), evidence-bundle ZIP (for auditor delivery)

### Production-grade distribution

- **GUI installer for Windows** (`argus-setup.exe`) with Add/Remove Programs entry, uninstall, clean PATH cleanup
- **Embedded Windows PE version info**: Company, Product, FileVersion, Copyright — Windows shows our publisher name in SmartScreen instead of "Unknown publisher"
- **Hardened Docker image** on Chainguard's `static` base — ~25 MB total, runs as non-root uid 65532, zero known CVEs in the base
- **Multi-arch Docker**: `linux/amd64` and `linux/arm64` in the same manifest tag — one pull, correct architecture auto-selected

---

## 💡 Quick demo

```bash
# One tenant
argus scan --tenant <id> --subscription <id>

# Every subscription in the tenant, parallel, single report
argus scan --tenant <id> --org-wide

# Focus on a specific compliance framework
argus scan --tenant <id> --subscription <id> --compliance soc2

# CI gate: exit non-zero if any CRITICAL chain or HIGH finding
argus scan --tenant <id> --subscription <id> --ci

# Pre-deployment: scan Terraform plan
terraform show -json plan.out > plan.json
argus iac plan.json

# Pre-deployment: scan a Bicep build
bicep build main.bicep
argus iac main.json

# Pre-deployment: preview the effect of a live deployment
az deployment group what-if --output json --resource-group rg --template-file main.bicep > whatif.json
argus iac whatif.json
```

---

## 🧭 Command reference — every command with an example

### `argus scan` — run a full scan

```bash
# Minimal: one subscription
argus scan --tenant <tenant-id> --subscription <sub-id>

# Every subscription in the tenant, in parallel
argus scan --tenant <tenant-id> --org-wide

# Scope by pillar
argus scan --tenant <id> --subscription <id> --pillar Identity,Network

# Target a specific compliance pack
argus scan --tenant <id> --subscription <id> --compliance soc2          # SOC 2
argus scan --tenant <id> --subscription <id> --compliance hipaa         # HIPAA
argus scan --tenant <id> --subscription <id> --compliance pci-dss-4     # PCI DSS 4.0
argus scan --tenant <id> --subscription <id> --compliance iso-27001     # ISO 27001

# Output formats
argus scan --tenant <id> --subscription <id> --output html              # default
argus scan --tenant <id> --subscription <id> --output json              # machine-readable
argus scan --tenant <id> --subscription <id> --output sarif             # GitHub code scanning
argus scan --tenant <id> --subscription <id> --evidence                 # + zipped auditor bundle

# Custom output directory
argus scan --tenant <id> --subscription <id> --output-dir ./my-reports

# Customise the Activity Log lookback window (default 30, Azure max 90)
argus scan --tenant <id> --subscription <id> --activity-log-days 7   # recent drift only
argus scan --tenant <id> --subscription <id> --activity-log-days 90  # full Azure retention

# CI gate mode — exit code 2 on HIGH+ findings or CRITICAL chains
argus scan --tenant <id> --subscription <id> --ci \
  --ci-critical-threshold 0 --ci-chain-threshold 0 --ci-min-score 70
```

### `argus scan --resume` — resume an interrupted scan

Long-running Entra / Graph scans sometimes hit throttling. ARGUS checkpoints each sub-collector on success so you can continue where you left off.

```bash
# See interrupted scans
argus scan --list-resumable

# Resume a specific scan id
argus scan --tenant <id> --subscription <id> --resume scan-20260418T102231Z-a1b2c3-1111
```

**Example output of `--list-resumable`:**
```
SCAN ID                                                 SUBSCRIPTION                          TENANT                                PENDING
scan-20260418T102231Z-a1b2c3-1111                       11111111-1111-1111-1111-111111111111  aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa  [identity policy] (3m ago)

Resume with:  argus scan --tenant <tenant> --subscription <sub> --resume <scan-id>
```

Checkpoints live at `~/.argus/scan-state/<scan-id>/` and are cleaned up after a full successful scan.

### `argus explain` — browse rules + chains from the terminal

```bash
# Full catalog of rules + chains
argus explain

# A specific rule
argus explain zt_net_001
argus explain cis_1_1

# A specific attack chain
argus explain CHAIN-001
argus explain CHAIN-200     # newest chain
```

**Example: `argus explain CHAIN-052`**
```
CHAIN-052  Guest user with group-based admin escalation
────────────────────────────────────────────────────────────────────────
Severity: HIGH   Likelihood: Medium   Logic: ALL

Why this chain matters
A guest user is invited to a group that transitively holds a privileged
Entra directory role. Because group-based role assignments inherit to
every direct and nested member, the guest gains tenant-wide privilege
the moment the invitation is accepted...

Trigger rules
  • zt_id_023
  • zt_id_024

Attack walkthrough
  Step 1. Accept an invitation for a guest user into the home tenant.
    actor: External tenant admin
    MITRE: T1078.004
    enabled by: zt_id_023
    gain: Guest foothold in the target tenant.
  ...

Blast radius
  Initial access    Guest invitation accepted.
  Max privilege     Entra directory admin role (User Admin, Application Admin, etc.).
  Data at risk      Directory data, App secrets, Email / Teams via consent exploitation
```

### `argus diff` — scan-to-scan drift

```bash
# Human-readable drift between two scan JSONs
argus diff --from ./argus-output/argus_20260401_100000.json \
           --to   ./argus-output/argus_20260418_100000.json

# Machine-readable
argus diff --from older.json --to newer.json --json
```

**Example output:**
```
Comparing:
  from  argus_20260401_100000.json
  to    argus_20260418_100000.json

Added findings: 1
  + ●  zt_vis_003          VirtualMachines  Defender Free tier

Resolved findings: 2
  - ●  zt_data_001         public-sa  Public blob
  - ●  zt_id_001           svc-sp     SP never expires

Added chains:    CHAIN-008
Resolved chains: CHAIN-001
```

### `argus serve` — local-only dashboard

Opens a web UI on loopback at `http://localhost:8080`. **Nothing leaves your machine.**

```bash
argus serve                                   # default: 127.0.0.1:8080
argus serve --addr :9000                      # custom port
argus serve --scan-dir ./my-reports           # point at a custom output dir
argus serve --addr 0.0.0.0:8080               # bind to all interfaces (use with care)
```

Views: Overview, Findings (filter / sort), Chains (drill-down narrative), Attack graph (interactive SVG), Compliance posture, Drift diff, Scan history. A **Run scan** button triggers `argus scan` in the background.

### `argus iac` — pre-deployment IaC scan (no Azure needed)

```bash
# Terraform plan
terraform show -json plan.out > plan.json
argus iac plan.json

# ARM template
argus iac template.json

# Bicep (compile first)
bicep build main.bicep
argus iac main.json

# ARM what-if (effective post-deploy state)
az deployment group what-if --output json --resource-group rg --template-file main.bicep > whatif.json
argus iac whatif.json

# CI gate on IaC
argus iac plan.json --fail-on HIGH
```

### `argus check-permissions` — preflight Graph + ARM scopes

```bash
argus check-permissions --tenant <id>                 # human-readable
argus check-permissions --tenant <id> --json          # for CI
```

Probes every Microsoft Graph + ARM endpoint ARGUS will use and reports exactly which scopes are missing. Fix them before scanning.

### `argus grant-permissions` — bootstrap the service principal (no separate script)

If you installed via `brew` / `scoop` / `winget` / EXE, the helper shell scripts aren't in your filesystem — but the binary has them embedded. This subcommand extracts the right one for your shell and runs it.

```bash
argus grant-permissions --subscription <id> --tenant <id>
argus grant-permissions --subscription <id> --tenant <id> --name my-argus-sp
argus grant-permissions --subscription <id> --tenant <id> --dry-run    # preview, don't run
```

**Up-front transparency:** the command prints every Azure RBAC role and every Microsoft Graph application permission it's about to request, with a short reason for each, **before** calling `az`:

```
ARGUS grant-permissions  creating service principal argus-scanner
  subscription : 00000000-0000-0000-0000-000000000001
  tenant       : aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
  shell        : bash

Azure RBAC roles (subscription scope):
  • Reader           — read every resource for posture analysis
  • Security Reader  — read Defender for Cloud findings + secure score

Microsoft Graph application permissions:
  • Directory.Read.All                   — Read users, groups, service principals for every identity rule
  • Application.Read.All                 — Detect App Registration takeover chains (CHAIN-002)
  • Policy.Read.All                      — Enumerate Conditional Access + Authentication policies
  • RoleManagement.Read.Directory        — Read Entra directory role assignments + PIM schedules
  • AccessReview.Read.All                — Verify access reviews exist for privileged roles
  • AuditLog.Read.All                    — Read sign-in + audit logs for stale-account detection
  • Group.Read.All                       — Walk nested group membership for privilege-path analysis
  • GroupMember.Read.All                 — Transitive member expansion — the #1 way Owner access hides
```

Prerequisites: `az` on PATH, logged in as Global Admin or Privileged Role Admin (so admin consent can be granted). `bash` systems also need `jq`. Idempotent — safe to re-run.

### `argus install` — one-shot self-installer

```bash
./argus-linux-amd64 install                 # downloads binary, puts it on PATH
argus install --force                       # re-run to refresh
```

Puts the binary in `~/.local/bin/argus` (Unix) or `%LOCALAPPDATA%\Programs\argus\argus.exe` (Windows) and patches PATH. No admin needed.

### `argus update` — self-updater (see Updating section above for every flag)

```bash
argus update                  # latest
argus update --version v1.0.0 # specific release
argus update --list           # available versions
argus update --check          # what's latest, don't install
```

### `argus monitor` — continuous scanning daemon

```bash
argus monitor --tenant <id> --subscription <id> --interval 1h
argus monitor --tenant <id> --subscription <id> --webhook https://hooks.slack.com/...
```

### `argus trend` — score trend over time

```bash
argus trend --subscription <id>           # ASCII chart of recent scans
argus trend --subscription <id> --since 30d
```

### `argus rules list` — browse the rule library offline

```bash
argus rules list                          # every rule, grouped
argus rules list --pillar Network         # just network rules
argus rules list --source zt              # just Zero Trust rules
argus rules list --compliance soc2        # just SOC 2-mapped rules
```

### `argus suppress` — add a rule suppression

```bash
argus suppress zt_net_001 --resource /subs/xxx/nsg/mgmt --reason "Approved mgmt jump box" --until 2026-06-30
```

Writes to `.argusignore`; respected by every future scan.

### `argus score` — silent single-line score

```bash
argus score --tenant <id> --subscription <id>
# → 62/100 · Grade D
```

### `argus server` — long-running HTTP API (different from `argus serve`)

```bash
argus server --addr :9090 --api-key $API_KEY
```

Multi-scan REST API for integration into other tools. Contrast with `argus serve` which is a UI-only local dashboard.

---

## 📊 How ARGUS compares

| | ARGUS | Checkov | Wiz | Defender for Cloud |
|---|---|---|---|---|
| **License** | Source-available (PolyForm Strict) | Apache 2.0 | Closed | Closed |
| **Cost** | Free | Free | $$$ | Pay-per-resource |
| **Runs where?** | Your laptop / CI / Docker | Your laptop / CI | SaaS | Azure-only |
| **Data leaves your env?** | **No** | No | Yes (SaaS) | Yes (Microsoft) |
| **Attack-chain correlation** | ✅ **200** (51 hand-authored + 149 data-driven) + graph pathfinder | ❌ | ✅ | ⚠️ Partial |
| **Cross-subscription paths** | ✅ | ❌ | ✅ | ❌ |
| **Nested group pathfinding** | ✅ | ❌ | ✅ | ❌ |
| **PIM Eligible/Active distinction** | ✅ | ❌ | ⚠️ Partial | ❌ |
| **IaC: Terraform plan** | ✅ 245 types | ✅ 150 types | ✅ | ❌ |
| **IaC: ARM template** | ✅ full expression interpreter | ✅ partial | ✅ | Native |
| **IaC: Bicep** | ✅ | ✅ | ⚠️ Partial | Native |
| **IaC: ARM what-if** | ✅ | ❌ | ❌ | N/A |
| **Compliance frameworks** | 4 (SOC 2, HIPAA, PCI 4, ISO 27001) at 100% rule coverage | CIS + NIST | SOC 2, ISO, NIST, HIPAA, PCI | Azure compliance center |
| **SLSA build-provenance** | ✅ Level 3 | ❌ | N/A | N/A |
| **Cosign-signed container** | ✅ | ❌ | N/A | N/A |
| **SBOM with every release** | ✅ SPDX 2.3 per binary | ❌ | N/A | N/A |
| **CVE scan on own image** | ✅ Trivy, release fails on HIGH/CRITICAL | ❌ | N/A | N/A |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        ARGUS (single binary)                  │
│                                                               │
│  ┌───────────────┐  ┌───────────────┐  ┌────────────────┐    │
│  │   Collector   │  │  OPA engine   │  │   Correlator   │    │
│  │               │  │               │  │                │    │
│  │ Resource      │  │ 245 Rego      │  │ 200 chain      │    │
│  │  Graph (ARM)  │→→│  policies     │→→│  patterns      │    │
│  │ Graph API     │  │               │  │                │    │
│  │ Defender      │  │ SOC2/HIPAA/   │  │ Graph          │    │
│  │ Activity Log  │  │  PCI/ISO      │  │  pathfinder    │    │
│  │ ARM RBAC      │  │  mappings     │  │  (BFS)         │    │
│  └───────────────┘  └───────────────┘  └────────────────┘    │
│         ↑                  ↓                  ↓               │
│  ┌──────────────┐   ┌─────────────┐   ┌─────────────────┐    │
│  │  Preflight   │   │  Findings   │   │  Chains +       │    │
│  │  + Auth      │   │  + evidence │   │  minimal-fix    │    │
│  │  check       │   │             │   │  recommendation │    │
│  └──────────────┘   └─────────────┘   └─────────────────┘    │
│                          ↓                                    │
│              HTML / JSON / SARIF / Evidence ZIP               │
└──────────────────────────────────────────────────────────────┘
```

All scan state stays in-process. No daemon. No SaaS callback. No telemetry.

---

## 🧰 IaC pre-deployment scanning

ARGUS runs against your IaC artifact before you `terraform apply` / `az deployment` — catch misconfigs while they're still 5 minutes of effort to fix, not a production incident.

| Format | Command | What it catches |
|---|---|---|
| Terraform plan | `terraform show -json plan.out > plan.json && argus iac plan.json` | Misconfigs in planned resources before apply |
| ARM template | `argus iac template.json` | Misconfigs in hand-written ARM |
| Bicep (compiled) | `bicep build main.bicep && argus iac main.json` | Misconfigs in Bicep-defined resources |
| ARM what-if | `az deployment group what-if --output json ... > whatif.json && argus iac whatif.json` | Effective post-deployment state, including Modify actions against existing resources |

CI gate example:
```bash
argus iac plan.json --fail-on HIGH  # exit code 2 if any HIGH/CRITICAL finding
```

---

## 🧪 Authentication

ARGUS uses the standard Azure credential chain — it picks up whichever works first:

1. `az login` (most common)
2. Environment-variable service principal: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`
3. Managed identity (when running inside Azure)
4. Visual Studio Code credentials

For CI use cases, a Service Principal with **Reader** on the target subscription + the Graph permissions listed below is the cleanest pattern.

### Microsoft Graph permissions needed for full coverage

| Permission | What breaks without it |
|---|---|
| `Directory.Read.All` | Every identity rule (users, groups, SPs) |
| `GroupMember.Read.All` | Nested group pathfinder walks |
| `Application.Read.All` | App Registration takeover chain (CHAIN-002) |
| `Policy.Read.All` | Conditional Access, legacy-auth, cross-tenant rules |
| `RoleManagement.Read.Directory` | Entra directory roles + PIM in pathfinder |
| `AccessReview.Read.All` | Access review existence rules |

Verify your current scopes before scanning:
```bash
argus check-permissions --tenant <id>
argus check-permissions --tenant <id> --json   # machine-readable for CI
```

Two ready-made scripts grant all of these to a Service Principal in a single run. They ship as release assets so you don't need to clone the repo — pick the one that matches your shell:

**macOS / Linux (bash / zsh):**
```bash
# Download
curl -LO https://github.com/vatsayanvivek/argus/releases/latest/download/setup-graph-permissions.sh
chmod +x setup-graph-permissions.sh
# Run
./setup-graph-permissions.sh --subscription <sub-id> --tenant <tenant-id>
```

**Windows PowerShell:**
```powershell
# Download
iwr https://github.com/vatsayanvivek/argus/releases/latest/download/setup-graph-permissions.ps1 -OutFile setup-graph-permissions.ps1
# Run
.\setup-graph-permissions.ps1 -SubscriptionId <sub-id> -TenantId <tenant-id>
```

Both scripts use the Azure CLI (`az`) — no PowerShell Az module, no bash-specific tooling. They're functionally identical; one is idiomatic for each shell. Both are visible on the [releases page](https://github.com/vatsayanvivek/argus/releases/latest) for every release.

---

## 📦 Branching + release model

Every release produces a permanent `release/vX.Y.Z` branch frozen at the release commit. See [MAINTAINERS.md](MAINTAINERS.md) for full details.

```
main          ──●───●───●──────────●────────●──────  always == latest release
                  ↘             ↘             ↘
release/v1.0.0    ●             │             │     frozen at v1.0.0
release/v1.1.0                  ●             │     frozen at v1.1.0
release/v1.2.0                                ●     frozen at v1.2.0
```

Users who pinned `v1.0.0` can always browse the exact source of that release via `git checkout release/v1.0.0`.

---

## 🎛️ Azure services ARGUS scans

Explicit, per-service coverage. Every bullet below is at least one Rego rule that fires on a misconfiguration of that service type. Services not listed are visible to ARGUS via Resource Graph but don't have dedicated rules yet — a future release closes the gap.

**Identity & access (IAM)**
- Microsoft Entra ID (users, groups, service principals, managed identities)
- Role-based access control (RBAC) — built-in and custom roles
- Privileged Identity Management (PIM) — eligible + active schedules
- Conditional Access policies
- App Registrations + service principal credentials
- Guest users + cross-tenant access policies
- Access reviews

**Data**
- Storage Accounts — blob public access, TLS floor, network rules, shared-key auth, Data Lake Gen2 HNS/ACLs
- Azure SQL Server + databases + managed instances
- Cosmos DB accounts
- Azure Database for PostgreSQL (single + flexible)
- Azure Database for MySQL (single + flexible)
- Azure Database for MariaDB
- Azure Cache for Redis — TLS 1.2, SSL-only port
- Synapse workspaces + SQL pools (dedicated + serverless) — TDE, public endpoint
- Data Factory — public access, integration runtime
- Databricks workspaces — secure cluster connectivity, no-public-IP
- Stream Analytics jobs — CMK encryption
- HDInsight clusters — public gateway
- Microsoft Purview accounts
- NetApp Files — NFS v3/v4.1 + Kerberos posture

**Networking**
- Virtual Networks + Subnets
- Network Security Groups (NSG) — inbound Allow rules, source IP restrictions
- Azure Firewall + Firewall Policy (threat intel, DNS proxy)
- Application Gateway — WAF mode, TLS policy
- Front Door — TLS 1.2 floor, WAF
- Azure Bastion
- Azure DDoS Protection Plans
- Private Endpoints + Private DNS zones (VNet link verification)
- VPN Gateway — Basic SKU deprecation, active-active, BGP
- ExpressRoute Circuits + ExpressRoute Direct ports (MACsec)
- Traffic Manager — HTTPS probes
- NAT Gateway — idle timeout
- Network Watcher

**Compute & workloads**
- Virtual Machines — disk encryption, managed identity, JIT VM access
- Virtual Machine Scale Sets — automatic OS upgrades, managed identity
- Azure Kubernetes Service (AKS) — private cluster, Azure AD RBAC, network policy
- Container Apps + Container App Environments — ingress, mTLS, managed identity
- Container Instances
- Container Registry — admin user, anonymous pull, zone redundancy
- App Service + Linux/Windows Web Apps — HTTPS only, min TLS, client cert
- Function App — HTTPS only, auth
- Azure Batch accounts — public network access
- Service Fabric clusters — Entra ID admin auth
- Managed Disks + Disk Encryption Sets

**AI / ML**
- Cognitive Services (incl. Azure OpenAI) — public access, local auth, CMK
- Azure Machine Learning Workspaces + compute clusters — CMK, public SSH
- Bot Service — managed identity auth

**Integration & messaging**
- API Management — TLS policy, managed identity, internal VNet mode, diagnostic logs
- Logic Apps — HTTP trigger IP restrictions
- Event Grid topics + domains — local auth (SAS)
- Event Hub namespaces — TLS, local auth
- Service Bus namespaces — TLS, local auth
- Azure Relay

**Observability**
- Log Analytics workspaces — retention, ingestion, local auth
- Activity Log Profiles + Diagnostic Settings (per resource type)
- Activity Log alerts — role assignment writes, Key Vault `listKeys`/`listSecrets`
- Microsoft Defender for Cloud — per-service pricing, secure score
- Network Watcher flow logs

**Security & governance**
- Microsoft Defender plans (Servers, SQL, Storage, Containers, App Service, Key Vault, ARM, DNS, open-source relational DBs, Cosmos, AI, APIM)
- Azure Policy assignments + definitions + exemptions
- Microsoft Sentinel (onboarding, alert rules, data connectors)
- Advanced Threat Protection
- Security Center contacts, auto-provisioning, subscription pricing

**Key management**
- Azure Key Vault — purge protection, soft delete, RBAC authorization, firewall, CMK usage
- Managed HSM
- Key Vault access policies + secrets + keys + certificates

**Backup & disaster recovery**
- Recovery Services Vaults — immutability, soft delete, CRR
- Backup policies — retention floor, geo-redundant storage
- Site Recovery replication policies — RPO threshold

**DevOps / platform**
- App Configuration stores — public access, local auth, CMK
- User-assigned managed identities

---

## 📤 What the output looks like

**Terminal summary** (always shown):

```
ARGUS scan │ elapsed 34s
────────────────────────────────────────────────────────────
 ✓ Azure resources (Resource Graph)       done    12s   — 87 resources enumerated
 ✓ Entra ID (users, groups, SPs, CAPs)    done    8s    — 42 users, 12 groups, 23 SPs
 ✓ Azure RBAC (ARM authorization)         done    4s    — 67 role assignments
 ✓ Microsoft Defender for Cloud           done    6s    — 14 findings, score 62/100
 ✓ Activity Log (30-day window)           done    11s   — 1,432 events
 ✓ Azure Policy compliance                done    3s    — 91 policies evaluated

╔═══════════════════════════════════════════════════════╗
║                 ARGUS summary                         ║
║                                                       ║
║  Findings:      42 (CRITICAL 3, HIGH 14, MED 20)      ║
║  Attack chains: 11 (CRITICAL 2, HIGH 6, MED 3)        ║
║  ZT Score:      62/100 (Grade D)                      ║
║                                                       ║
║  Top-3 minimal fixes that break most chains:          ║
║    1. Enable MFA on 8 no-MFA users (breaks 7 chains)  ║
║    2. Disable Storage public access    (breaks 4)     ║
║    3. Remove 2 guest users with UAA    (breaks 3)     ║
╚═══════════════════════════════════════════════════════╝
```

**HTML report**: audit-ready, per-resource findings, chain narratives with personalised actor + target names, minimal-fix recommendations, per-framework compliance coverage tables.

**JSON report**: every finding and chain with full metadata — rule ID, severity, pillar, MITRE ATT&CK technique, chain role, compliance control citations across SOC 2, HIPAA, PCI, ISO.

**SARIF** (GitHub Security tab): standard SARIF 2.1.0 so findings land in Pull Request annotations.

**Evidence bundle ZIP** (auditor delivery): per-framework subdirectories with findings mapped to controls plus a coverage summary.

---

## ❓ FAQ

**Q: How long does a scan take?**
A: 30s–2min for a typical single-subscription tenant (~100 resources, ~50 users). `--org-wide` scans every subscription in parallel; wall time is dominated by the largest subscription. On a 5,000-resource estate it takes ~4 min.

**Q: What's the resource footprint?**
A: ~80 MB RAM during scan, mostly OPA's compiled query cache. No disk writes except the output directory. No daemon, no background processes.

**Q: Does ARGUS send any telemetry?**
A: No. Not to us, not to Microsoft, not to anyone. The binary only talks to Azure endpoints and — for `argus update` — GitHub Releases API. Verifiable via packet capture.

**Q: Will `argus scan` modify anything in my Azure environment?**
A: No. Every API call is read-only. Activity Log will show `GET`s only; no `PUT`/`POST`/`DELETE`.

**Q: What Azure privileges does the scanning identity need?**
A: `Reader` on every subscription you want to scan, plus the Microsoft Graph permissions listed in [Authentication](#-authentication). No write permissions.

**Q: Is ARGUS safe to run against production?**
A: Yes. Read-only. Sub-linear Azure API consumption. You can run it every hour without pressure.

**Q: Why does Windows say "Unknown publisher"?**
A: Because the binary isn't Authenticode-signed yet (we have PE metadata embedded, which is a different thing). Details in Trust & verification above. Click *Run anyway* once; SmartScreen remembers. Docker image has no such issue.

**Q: How do I contribute a new rule?**
A: Open a GitHub Issue. Direct PRs aren't accepted (PolyForm Strict license), but feature requests + detailed issue descriptions are welcome and often implemented.

**Q: Can I pin an older version?**
A: Yes — `argus update --version v1.0.0` downgrades or pins. Each release has a permanent `release/vX.Y.Z` branch and the binaries stay on the GitHub release page.

---

## 🛠️ Troubleshooting

**"Azure unreachable" or "context deadline exceeded"**:
The preflight check catches this and names the likely cause. Usually:
- Corporate proxy not set — `export HTTPS_PROXY=http://proxy:port`
- TLS-inspecting gateway missing root CA — ask IT for corporate root CA
- Firewall blocking outbound 443 — open `management.azure.com`, `graph.microsoft.com`, `login.microsoftonline.com`
- `argus check-permissions --tenant <id>` probes each endpoint individually

**"Windows protected your PC" SmartScreen**:
Expected for unsigned binaries. *More info* → *Run anyway* — once per binary.

**Docker: "Cannot connect to the Docker daemon"**:
Docker Desktop isn't running. Start it, or use the native binary via `argus install`.

**"No Azure credential available"**:
`az login` on the host, or set `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` for a Service Principal.

**Graph permissions limited warning in the report**:
Some rules couldn't run because the scanning identity lacks a Graph scope. `argus check-permissions --tenant <id>` shows exactly which. Grant them with one download + run — no repo clone needed, the scripts ship as release assets:

- **macOS / Linux**: `curl -LO https://github.com/vatsayanvivek/argus/releases/latest/download/setup-graph-permissions.sh && bash setup-graph-permissions.sh --subscription <id> --tenant <id>`
- **Windows PowerShell**: `iwr https://github.com/vatsayanvivek/argus/releases/latest/download/setup-graph-permissions.ps1 -OutFile grant.ps1; .\grant.ps1 -SubscriptionId <id> -TenantId <id>`

**macOS: "cannot be opened because the developer cannot be verified"**:
Right-click → Open → Open. Or `xattr -d com.apple.quarantine argus-darwin-arm64`.

---

## 🔒 Privacy & data handling

ARGUS is designed around one principle: **your tenant data never leaves your machine.**

| What leaves your machine? | To where? | Why? |
|---|---|---|
| Azure API calls (ARM, Graph, Defender) | `*.azure.com`, `graph.microsoft.com`, `login.microsoftonline.com` | To read your tenant's state |
| `argus update` checks | `api.github.com` + `github.com/releases` | To check for and download newer binaries |
| Everything else | Nowhere | No telemetry, no analytics, no phone-home |

No tenant identifiers, resource names, findings, or configurations are ever transmitted to any third party. The maintainer does not operate any backend service that receives ARGUS data. The binary's network profile is auditable via packet capture.

---

## 📄 License

ARGUS is source-available under the [**PolyForm Strict License 1.0.0**](LICENSE).

You may:
- ✅ Download and run the binaries
- ✅ Read every line of source code
- ✅ Use the generated reports in your own compliance work
- ✅ Reference ARGUS in research / talks

You may **not**:
- ❌ Fork, modify, or redistribute modified versions
- ❌ Vendor or embed the source into another project
- ❌ Re-release the binary under a different name
- ❌ Submit Pull Requests (the repo doesn't accept external code contributions)

Bug reports and feature requests via GitHub Issues are welcome.

---

## 🔗 Quick links

- **Docs site (rule + chain catalog)**: https://vatsayanvivek.github.io/argus/
- **Releases**: https://github.com/vatsayanvivek/argus/releases
- **Docker image**: https://ghcr.io/vatsayanvivek/argus
- **SBOMs (every release)**: attached as `argus-<platform>.sbom.spdx.json` to each release
- **SLSA attestations**: https://github.com/vatsayanvivek/argus/attestations
- **Sigstore transparency**: https://search.sigstore.dev/?query=vatsayanvivek%2Fargus
- **Security disclosures**: [SECURITY.md](SECURITY.md)
- **Branching / maintainer notes**: [MAINTAINERS.md](MAINTAINERS.md)
- **Issue tracker**: https://github.com/vatsayanvivek/argus/issues
- **Reputation-building checklist**: [scripts/reputation-building.md](scripts/reputation-building.md)

---

<div align="center">

**ARGUS** — *finds what happens when Azure misconfigurations combine.*

Made for teams who want to know exactly how an attacker would move — before an attacker does.

</div>
