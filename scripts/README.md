# ARGUS Setup Scripts

Helper scripts for bootstrapping the Azure environment that ARGUS needs to
perform a full-fidelity scan.

## 1. Purpose

ARGUS is a Go-based Azure security scanner that correlates findings across
Azure Resource Manager, Defender for Cloud, and Microsoft Graph into attack
chains. Several of its highest-value detections require **application-level
Microsoft Graph permissions** that are not granted to a standard Reader:

- **CHAIN-002 - App Registration Graph abuse to tenant data** - Detects
  App Registrations holding unsanctioned high-privilege Graph permissions
  (e.g., a rogue service principal with `Directory.ReadWrite.All` or
  `RoleManagement.ReadWrite.Directory`) that can be chained with other
  findings into a tenant-takeover path. This detection relies entirely on
  `Application.Read.All`.
- Conditional Access policy drift checks (`Policy.Read.All`)
- PIM eligibility / active role walks (`RoleManagement.Read.Directory`)
- Risky user correlation (`IdentityRiskyUser.Read.All`)
- Defender for Cloud alert ingestion (`SecurityEvents.Read.All`)

These scripts create a dedicated Service Principal (SPN), assign it the
Azure RBAC roles ARGUS needs, add and grant admin-consent for the eight
Microsoft Graph application permissions, mint a 1-year client secret, and
verify the result. A bash and PowerShell version are provided for parity
across platforms; both drive the **Azure CLI (`az`)** under the hood so the
prerequisite footprint is minimal.

## 2. Prerequisites

### Tools

- **Azure CLI** - install from <https://aka.ms/InstallAzureCLI>
  ```bash
  az --version
  ```
- **`jq`** (bash script only) - `brew install jq` / `apt install jq` /
  `yum install jq`
- You must be logged in to Azure:
  ```bash
  az login --tenant <tenant_id>
  ```

### Azure roles on your account

You must hold all three of the following (or their equivalents) before
running the script:

| Purpose | Required role (one of) |
|---|---|
| Create the SPN and register API permissions | **Application Administrator** OR **Cloud Application Administrator** |
| Assign Reader and Security Reader at subscription scope | **User Access Administrator** OR **Owner** on the target subscription |
| Grant admin consent for the Microsoft Graph permissions | **Privileged Role Administrator** OR **Global Administrator** |

If you only hold some of these, the script will still run - it just won't
be able to complete the steps you lack privileges for. It reports each
failure clearly and prints remediation hints.

## 3. Usage

### Bash

```bash
./scripts/setup-graph-permissions.sh <subscription_id> <tenant_id> [spn_name]
```

Example:

```bash
./scripts/setup-graph-permissions.sh \
    00000000-0000-0000-0000-000000000000 \
    11111111-1111-1111-1111-111111111111 \
    argus-scanner
```

### PowerShell

```powershell
./scripts/setup-graph-permissions.ps1 -SubscriptionId <id> -TenantId <id>
```

Or with a custom display name:

```powershell
./scripts/setup-graph-permissions.ps1 `
    -SubscriptionId 00000000-0000-0000-0000-000000000000 `
    -TenantId      11111111-1111-1111-1111-111111111111 `
    -SpnName       argus-scanner
```

Both scripts are idempotent-ish: re-running with the same `spn_name` will
create a **new** service principal with the same display name (Azure AD
allows duplicates). If you want to reuse an existing SPN, delete the old
one first (see "Revoking the SPN" below).

## 4. Permissions granted and why

The SPN receives the following application-level Microsoft Graph
permissions (all `Role` type, i.e., granted to the SPN itself with admin
consent - not delegated):

| Permission | Purpose |
|---|---|
| `SecurityEvents.Read.All` | Read Defender for Cloud alerts |
| `Directory.Read.All` | Enumerate users, groups, service principals |
| `Policy.Read.All` | Read conditional access policies, tenant settings |
| `IdentityRiskyUser.Read.All` | Detect risky users for chain correlation |
| `RoleManagement.Read.Directory` | Read PIM eligible/active assignments |
| `Application.Read.All` | **Detect CHAIN-002 - App Registrations holding high-privilege Microsoft Graph permissions that lead to tenant takeover** |
| `AuditLog.Read.All` | Drift analysis activity log queries |
| `Reports.Read.All` | Sign-in report data |

At the Azure RBAC layer the SPN also gets:

- **Reader** at the target subscription scope - required by every ARGUS
  resource enumeration call.
- **Security Reader** at the target subscription scope - required to read
  Defender for Cloud secure-score, recommendations, and regulatory
  compliance state.

## 5. Using the output with ARGUS

The script ends by printing a credential block. Export those variables
and run ARGUS:

```bash
export AZURE_TENANT_ID="..."
export AZURE_CLIENT_ID="..."
export AZURE_CLIENT_SECRET="..."
export AZURE_SUBSCRIPTION_ID="..."

./argus scan --subscription <id> --tenant <id>
```

Alternatively, you can use `az login` interactively (no env vars at all).
ARGUS will fall back to the `DefaultAzureCredential` chain and pick up your
CLI session - **but** you will then only get whatever Microsoft Graph
permissions your user account already has, which generally means CHAIN-002
(App Registration takeover) and the other Graph-heavy detections will be
incomplete. The SPN route is recommended for any non-interactive or
high-fidelity scan.

## 6. Revoking the SPN

When you're done with the SPN (or ahead of an engagement wrap-up), clean
it up:

```bash
# Delete the application + its service principal object
az ad sp delete --id <app_id>
```

And remove any lingering role assignments at the subscription scope:

```bash
az role assignment delete \
    --assignee <app_id> \
    --scope /subscriptions/<sub>
```

Deleting the SP automatically revokes the Graph API permissions that were
granted to it.

## 7. Troubleshooting

### `Insufficient privileges to complete the operation` on admin-consent

Your account is not a Global Administrator or Privileged Role
Administrator. The SPN and its permission *requests* will exist, but
nothing can consume them until an admin grants consent. Ask an admin to
open:

> Azure Portal -> Azure Active Directory -> App registrations ->
> argus-scanner -> API permissions -> **Grant admin consent for \<tenant\>**

### `Resource '...' does not exist or one of its queried reference-property objects are not present`

Azure AD replication lag. Wait 60 seconds and re-run just the failing
step. The script already retries role assignment five times with
back-off, but on very slow tenants it can still exceed that window.

### `App not found` / `The application with appId '...' was not found`

SPN creation may have failed silently. Check whether an object actually
exists:

```bash
az ad sp list --display-name argus-scanner -o table
```

If no rows come back, re-run the script. If duplicates appear, delete
the stale ones with `az ad sp delete --id <appId>`.

### `AADSTS7000215: Invalid client secret`

The client secret printed at the end is shown exactly once. If you lost
it, mint a new one:

```bash
az ad app credential reset --id <app_id> --years 1
```

This rotates the secret and prints a fresh one; update your env vars
accordingly.

### Graph verification step prints `[FAIL]`

The final verification probe uses *your* caller token, not the SPN's
(testing the SPN itself would require an extra `az login
--service-principal` round-trip). A 403 at that step usually just means
admin consent hasn't propagated tenant-wide yet - give it 60 seconds and
retry, or re-run the probe by hand:

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/applications?$top=1'
```
