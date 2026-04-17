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

211 policies. 51 hand-authored attack chains. A graph pathfinder that discovers chains nobody wrote down. IaC pre-deployment scanning across Terraform, ARM, Bicep, and ARM what-if. Four compliance packs (SOC 2, HIPAA, PCI DSS 4.0, ISO 27001:2022) with 100% rule-to-control coverage. Zero telemetry, no SaaS, no data ever leaves your laptop.

---

## 🎯 At a glance

| | |
|---|---|
| **211 policies** | 91 CIS Azure 2.0 + 120 Zero Trust native rules |
| **51 attack chains** | Hand-authored patterns with personalised narratives |
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

### Keeping it updated
```bash
argus update          # pull latest release, verify SHA-256, swap in place
argus update --list   # see available versions
argus update --check  # see latest without installing
```

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

- **51 hand-authored attack chains** with personalised narratives ("A guest user from tenant X with the UAA role on your production subscription, combined with your Key Vault's firewall rule allowing Azure Services, lets an attacker...")
- **Graph-based pathfinder** auto-discovers chains nobody wrote down:
  - **Nested group walks**: user → inner group → outer group → role assignment → scope (the #1 way Owner access hides in real environments)
  - **Entra directory roles**: Global Admin / Privileged Role Admin / Application Admin at tenant root, recognised with tenant-takeover weight 10
  - **PIM Eligible + Active**: PIM assignments become graph edges with an activation-step confidence penalty
  - **Cross-subscription edges**: when scanning org-wide, a user with Owner on sub A and UAA on sub B surfaces as a combined-reach chain
  - **NSG-derived exposure**: NSG inbound Allow-from-internet rules produce weighted exposes_to edges to VMs, AKS, App Services
  - **Calibration regression**: 4 canonical attacker patterns tested in CI guarantee weight changes never silently drop a real chain
- **Minimal-fix recommendation**: break the most chains with the fewest changes — pareto-ranked by blast radius

### Rules engine

- **211 policies** (91 CIS Azure 2.0 + 120 ARGUS Zero Trust)
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
- **100% rule-to-control coverage**: every one of the 211 rules cites at least one control in each of the 4 frameworks
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

## 📊 How ARGUS compares

| | ARGUS | Checkov | Wiz | Defender for Cloud |
|---|---|---|---|---|
| **License** | Source-available (PolyForm Strict) | Apache 2.0 | Closed | Closed |
| **Cost** | Free | Free | $$$ | Pay-per-resource |
| **Runs where?** | Your laptop / CI / Docker | Your laptop / CI | SaaS | Azure-only |
| **Data leaves your env?** | **No** | No | Yes (SaaS) | Yes (Microsoft) |
| **Attack-chain correlation** | ✅ 51 hand-authored + graph pathfinder | ❌ | ✅ | ⚠️ Partial |
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
│  │ Resource      │  │ 211 Rego      │  │ 51 chain       │    │
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

`scripts/setup-graph-permissions.sh` will grant all of these to a Service Principal in one run.

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
