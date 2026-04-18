# Troubleshooting

Common issues and fixes. Still stuck? [Open an issue](https://github.com/vatsayanvivek/argus/issues).

## Authentication

### `DefaultAzureCredential: failed to authenticate`

ARGUS walks the standard Azure credential chain. Try them in order:

```bash
# 1. Azure CLI login
az login

# 2. Service principal env vars
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
export AZURE_TENANT_ID=...

# 3. If on an Azure VM / AKS pod, managed identity is automatic
```

Confirm which path worked:

```bash
argus check-permissions --verbose
```

### `403 Forbidden` on Azure Resource Graph

Your principal lacks `Reader` at the subscription scope. Fix:

```bash
az role assignment create \
  --assignee <principal-id> \
  --role "Reader" \
  --scope /subscriptions/<sub-id>
```

### `401 Unauthorized` on Microsoft Graph

Missing Graph API scopes. Download the helper script from the latest release:

=== "Bash"

    ```bash
    curl -LO https://github.com/vatsayanvivek/argus/releases/latest/download/setup-graph-permissions.sh
    bash setup-graph-permissions.sh
    ```

=== "PowerShell"

    ```powershell
    iwr https://github.com/vatsayanvivek/argus/releases/latest/download/setup-graph-permissions.ps1 -OutFile setup-graph-permissions.ps1
    ./setup-graph-permissions.ps1
    ```

## Scan errors

### "Entra ID collection timeout"

Graph throttled a large tenant. Increase the timeout:

```bash
argus scan --graph-timeout 600s
```

Tier A9 ships `--resume` to pick up where a throttled scan left off.

### "Scan succeeded but the report is empty"

Rare. Check:

1. Did preflight report missing scopes? `argus check-permissions`
2. Did `--min-severity` filter everything out? Rerun without it.
3. Did a `--pillar` or `--compliance` filter match zero rules? Run bare `argus scan` once
   to confirm some findings exist.

### "Rule loaded but never fires"

Use the engine debug flag:

```bash
ARGUS_DEBUG_RULES=1 argus scan 2>&1 | grep <rule-id>
```

If you see `[argus-rules] parse <file>` errors the Rego is broken. If you see `prep`
failures the rule evaluates but can't be prepared for evaluation — usually a missing
`import future.keywords.in`. File a bug.

## Windows

### "Windows protected your PC — Unknown publisher"

SmartScreen flags unsigned binaries. See [Trust](trust.md) for how to verify the binary
via SHA-256 + cosign. Once verified, click "More info → Run anyway." This is roadmap for
signing.

### "Defender flagged argus.exe"

False positive — Defender heuristics sometimes flag small Go binaries. Submit to
Microsoft's false-positive reporter and add a Defender exclusion. If your org's Defender
tenant blocks it centrally, ask your SOC to submit a clean-reputation request.

### `argus install` fails with "Access denied"

Run the shell as administrator. `argus install` writes to a system PATH location.

## Docker

### "no such file or directory" when mounting ~/.azure

On macOS and Windows, `~/.azure` may not exist. Log in first:

```bash
az login
ls ~/.azure   # confirm config directory created
```

### Image fails to pull

```
Error: denied: denied
```

GHCR may rate-limit anonymous pulls. Log in:

```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u <your-github-user> --password-stdin
```

Or pin to a specific tag and use `docker pull` only once — Docker caches locally.

### "Permission denied" writing to /out

The image runs as uid 65532 (`nonroot`). Make your host output dir writable:

```bash
mkdir -p argus-output
chmod 777 argus-output
docker run -v "$(pwd)/argus-output:/out" ...
```

## Performance

### Scan is slow on a 10k-resource subscription

Expected. Entra ID + Defender for Cloud dominate. Options:

- Scope to specific pillars: `--pillar Identity,Network`
- Scope to specific subscription: `--subscription <id>`
- Use Azure Cloud Shell to run closer to the APIs
- Wait for Tier A9 (resume / parallel collectors)

### HTML report is huge

The report is self-contained and embeds raw evidence. Truncate evidence:

```bash
argus scan --evidence-size small
```

Or switch to JSON and render your own views:

```bash
argus scan --format json | jq '.findings[] | select(.severity == "CRITICAL")'
```

## Reporting bugs

1. Run with `ARGUS_DEBUG_RULES=1` and capture stderr.
2. Attach the tail of stderr to the issue.
3. Include the output of `argus --version` and `uname -a` (or `ver` on Windows).
4. **Never** attach a raw scan — it contains tenant data. Redact or scrub first.
