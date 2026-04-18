# Quick start

You have `argus` installed. Here's how to run your first scan in under 60 seconds.

## 1. Authenticate to Azure

ARGUS uses the standard Azure credential chain — whatever works for `az` works for `argus`.

=== "Azure CLI"

    ```bash
    az login
    ```

=== "Service principal"

    ```bash
    export AZURE_CLIENT_ID=<app-id>
    export AZURE_CLIENT_SECRET=<client-secret>
    export AZURE_TENANT_ID=<tenant-id>
    ```

=== "Managed identity"

    Nothing to do — ARGUS detects the MI automatically when running on an Azure VM,
    AKS pod, or Container App.

## 2. Check your permissions (optional but recommended)

```bash
argus check-permissions
```

This probes every Microsoft Graph and ARM endpoint ARGUS will use and reports which
scopes are missing. Fix any gaps first — a partial scan is misleading.

## 3. Run the scan

```bash
argus scan
```

You'll see:

- A cyan banner as ARGUS starts up
- Per-service progress (Resource Graph, Identity, Defender, etc.)
- A live-updating elapsed time
- A findings summary + chain count when done
- An HTML report at `./argus-output/argus_<timestamp>.html`

## 4. Read the report

Open the generated HTML in a browser:

```bash
# macOS
open argus-output/argus_*.html

# Linux
xdg-open argus-output/argus_*.html

# Windows
start argus-output\argus_*.html
```

The report has:

- **Executive summary** — severity breakdown, top findings, overall posture
- **Attack chains** — end-to-end narratives of what a real attacker could do
- **Findings** — every Rego rule that fired, grouped by pillar
- **Compliance** — SOC 2 / HIPAA / PCI / ISO control citations
- **Evidence** — per-finding raw configuration data

## 5. Targeted scans

```bash
# IaC only — no live Azure needed
argus scan --iac-only --iac-path ./infrastructure

# Specific subscription
argus scan --subscription <sub-id>

# Filter by severity
argus scan --min-severity HIGH

# Filter by pillar
argus scan --pillar Identity,Network

# Run a specific compliance pack
argus scan --compliance soc2
```

## 6. Output formats

```bash
argus scan --format html       # default
argus scan --format json       # machine-readable
argus scan --format sarif      # GitHub code scanning
argus scan --format evidence   # zipped audit bundle
```

## Common flags

| Flag | What it does |
|---|---|
| `--out <dir>` | Output directory (default `./argus-output/`) |
| `--format <fmt>` | `html` / `json` / `sarif` / `evidence` |
| `--min-severity <sev>` | Skip findings below this level |
| `--pillar <list>` | Only run rules from these pillars |
| `--compliance <pack>` | Run only rules mapped to a framework |
| `--iac-only` | Skip live Azure, scan IaC only |
| `--iac-path <dir>` | Directory containing `.tf`, `.bicep`, `.json` |
| `--resume` | Resume an interrupted scan (Tier A9) |

Run `argus scan --help` for the complete list.

## Next steps

- [Wire into CI / CD](cicd.md)
- [Run ARGUS in Docker](docker.md)
- [Browse the rule catalog](rules/index.md)
- [Review compliance coverage](compliance.md)
