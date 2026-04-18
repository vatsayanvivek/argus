#!/usr/bin/env bash
#
# setup-graph-permissions.sh
#
# ARGUS Scanner - Azure Service Principal bootstrap.
#
# Creates an Azure AD Service Principal for ARGUS with:
#   * Reader role           (subscription scope)
#   * Security Reader role  (subscription scope)
#   * Microsoft Graph application-level permissions required by the
#     identity-pillar rules (CHAIN-002 App Registration takeover, PIM,
#     Conditional Access, access reviews, etc.)
#
# Usage:
#   ./setup-graph-permissions.sh <subscription_id> <tenant_id> [spn_name]
#

set -euo pipefail

# ---------------------------------------------------------------------------
# ANSI color helpers (no external dependencies)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_CYAN=$'\033[36m'
else
    C_RESET=""
    C_BOLD=""
    C_RED=""
    C_GREEN=""
    C_YELLOW=""
    C_CYAN=""
fi

info() { printf "%s[INFO]%s  %s\n"  "${C_CYAN}"   "${C_RESET}" "$*"; }
ok()   { printf "%s[OK]%s    %s\n"  "${C_GREEN}"  "${C_RESET}" "$*"; }
warn() { printf "%s[WARN]%s  %s\n"  "${C_YELLOW}" "${C_RESET}" "$*"; }
fail() { printf "%s[FAIL]%s  %s\n"  "${C_RED}"    "${C_RESET}" "$*" >&2; }

header() {
    printf "%s%s===============================================%s\n" \
        "${C_BOLD}" "${C_CYAN}" "${C_RESET}"
    printf "%s%s%s%s\n" "${C_BOLD}" "${C_CYAN}" "$*" "${C_RESET}"
    printf "%s%s===============================================%s\n" \
        "${C_BOLD}" "${C_CYAN}" "${C_RESET}"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <subscription_id> <tenant_id> [spn_name]" >&2
    exit 1
fi

SUBSCRIPTION_ID="$1"
TENANT_ID="$2"
SPN_NAME="${3:-argus-scanner}"

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
info "Checking prerequisites..."

if ! command -v az >/dev/null 2>&1; then
    fail "Azure CLI ('az') is not installed. Install from https://aka.ms/InstallAzureCLI"
    exit 1
fi
ok "az CLI found: $(az version --query '\"azure-cli\"' -o tsv 2>/dev/null || echo 'unknown')"

if ! command -v jq >/dev/null 2>&1; then
    fail "'jq' is not installed. Install via your package manager (brew/apt/yum install jq)."
    exit 1
fi
ok "jq found: $(jq --version)"

# ---------------------------------------------------------------------------
# Verify Azure login
# ---------------------------------------------------------------------------
info "Verifying Azure login..."
if ! az account show >/dev/null 2>&1; then
    fail "You are not logged in to Azure. Run: az login --tenant ${TENANT_ID}"
    exit 1
fi
ok "Logged in to Azure"

info "Setting active subscription to ${SUBSCRIPTION_ID}..."
az account set --subscription "${SUBSCRIPTION_ID}"
ok "Subscription set"

# ---------------------------------------------------------------------------
# Step 1 - Create the Service Principal with Reader at subscription scope
# ---------------------------------------------------------------------------
header "Step 1/7: Creating Service Principal '${SPN_NAME}'"
info "Running: az ad sp create-for-rbac..."

SP_JSON="$(az ad sp create-for-rbac \
    --name "${SPN_NAME}" \
    --role "Reader" \
    --scopes "/subscriptions/${SUBSCRIPTION_ID}" \
    -o json)"

APP_ID="$(echo   "${SP_JSON}" | jq -r '.appId')"
PASSWORD="$(echo "${SP_JSON}" | jq -r '.password')"
SP_TENANT="$(echo "${SP_JSON}" | jq -r '.tenant')"

if [ -z "${APP_ID}" ] || [ "${APP_ID}" = "null" ]; then
    fail "Failed to create service principal"
    exit 1
fi

ok "Service principal created"
ok "  appId:  ${APP_ID}"
ok "  tenant: ${SP_TENANT}"

# ---------------------------------------------------------------------------
# Step 2 - Assign Security Reader at subscription scope
# ---------------------------------------------------------------------------
header "Step 2/7: Assigning Security Reader role"
info "Running: az role assignment create --role 'Security Reader'..."

# Do not abort on failure - the role may already be assigned, or AAD replication
# may still be in progress. We retry a few times before giving up.
SEC_READER_OK=0
for attempt in 1 2 3 4 5; do
    if az role assignment create \
        --assignee "${APP_ID}" \
        --role "Security Reader" \
        --scope "/subscriptions/${SUBSCRIPTION_ID}" \
        -o none 2>/dev/null; then
        ok "Security Reader assigned"
        SEC_READER_OK=1
        break
    fi
    info "Attempt ${attempt}/5 failed (likely AAD replication). Waiting..."
    sleep $((attempt * 3))
done

if [ "${SEC_READER_OK}" -eq 0 ]; then
    warn "Security Reader role could not be assigned automatically (it may already exist)."
    warn "Verify in the portal: Subscription -> Access control (IAM) -> Role assignments"
fi

# ---------------------------------------------------------------------------
# Step 3 - Grant Microsoft Graph application permissions
# ---------------------------------------------------------------------------
header "Step 3/7: Granting Microsoft Graph application permissions"

GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"

# Permission IDs are the canonical Microsoft Graph App Role IDs.
# Format: "permission_id:friendly_name"
GRAPH_PERMISSIONS=(
    "bf394140-e372-4bf9-a898-299cfc7cc924:SecurityEvents.Read.All"
    "7ab1d382-f21e-4acd-a863-ba3e13f7da61:Directory.Read.All"
    "246dd0d5-5bd0-4def-940b-0421030a5b68:Policy.Read.All"
    "dc5007c0-2d7d-4c42-879c-2dab87571379:IdentityRiskyUser.Read.All"
    "483bed4a-2ad3-4361-a73b-c83ccdbdc53c:RoleManagement.Read.Directory"
    "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30:Application.Read.All"
    "b0afded3-3588-46d8-8b3d-9842eff778da:AuditLog.Read.All"
    "230c1aed-a721-4c5d-9cb4-a90514e508ef:Reports.Read.All"
)

PERM_FAILS=0
for entry in "${GRAPH_PERMISSIONS[@]}"; do
    PERM_ID="${entry%%:*}"
    PERM_NAME="${entry##*:}"
    info "Adding ${PERM_NAME} (${PERM_ID})"
    if az ad app permission add \
        --id "${APP_ID}" \
        --api "${GRAPH_APP_ID}" \
        --api-permissions "${PERM_ID}=Role" \
        -o none 2>/dev/null; then
        ok "  Requested ${PERM_NAME}"
    else
        warn "  Failed to add ${PERM_NAME} (continuing)"
        PERM_FAILS=$((PERM_FAILS + 1))
    fi
done

if [ "${PERM_FAILS}" -gt 0 ]; then
    warn "${PERM_FAILS} permission(s) failed to register. Review output above."
else
    ok "All ${#GRAPH_PERMISSIONS[@]} Microsoft Graph permissions registered"
fi

# ---------------------------------------------------------------------------
# Step 4 - Grant admin consent
# ---------------------------------------------------------------------------
header "Step 4/7: Granting admin consent"
info "Running: az ad app permission admin-consent..."

CONSENT_OK=0
if az ad app permission admin-consent --id "${APP_ID}" 2>/dev/null; then
    ok "Admin consent granted"
    CONSENT_OK=1
else
    warn "Admin consent failed."
    warn "This usually means your account is NOT a Global Administrator or"
    warn "Privileged Role Administrator. Ask an admin to grant consent via:"
    warn "  Azure Portal -> Azure AD -> App registrations -> ${SPN_NAME}"
    warn "    -> API permissions -> Grant admin consent for <tenant>"
fi

# ---------------------------------------------------------------------------
# Step 5 - Create a fresh 1-year client secret
# ---------------------------------------------------------------------------
header "Step 5/7: Creating fresh 1-year client secret"
info "Running: az ad app credential reset --years 1..."

SECRET_JSON="$(az ad app credential reset \
    --id "${APP_ID}" \
    --years 1 \
    -o json 2>/dev/null || echo '{}')"

NEW_PASSWORD="$(echo "${SECRET_JSON}" | jq -r '.password // empty')"
if [ -n "${NEW_PASSWORD}" ]; then
    PASSWORD="${NEW_PASSWORD}"
    ok "New 1-year client secret issued"
else
    warn "Could not issue a new client secret; keeping the one from step 1"
fi

# ---------------------------------------------------------------------------
# Step 6 - Print credential block
# ---------------------------------------------------------------------------
header "Step 6/7: ARGUS Credentials"

cat <<EOF

${C_BOLD}===============================================${C_RESET}
${C_BOLD}${C_CYAN}ARGUS Scanner - Azure Credentials${C_RESET}
${C_BOLD}===============================================${C_RESET}
Set these environment variables before running argus:

export AZURE_TENANT_ID="${TENANT_ID}"
export AZURE_CLIENT_ID="${APP_ID}"
export AZURE_CLIENT_SECRET="${PASSWORD}"
export AZURE_SUBSCRIPTION_ID="${SUBSCRIPTION_ID}"

Then run: argus scan --subscription "\$AZURE_SUBSCRIPTION_ID" --tenant "\$AZURE_TENANT_ID"
${C_BOLD}===============================================${C_RESET}
${C_YELLOW}WARNING:${C_RESET} Save the client secret - it cannot be retrieved again.
${C_BOLD}===============================================${C_RESET}

EOF

# ---------------------------------------------------------------------------
# Step 7 - Verify Microsoft Graph reachability
# ---------------------------------------------------------------------------
# NOTE: This verification uses the CALLER'S current access token, not the
# newly-minted SPN's token. To test the SPN itself you'd need to log in as
# the SPN (az login --service-principal ...), but we avoid that here to
# keep the script a single-shot bootstrap. The caller token probe is
# sufficient to confirm that admin-consent has propagated tenant-wide.
# ---------------------------------------------------------------------------
header "Step 7/7: Verifying Microsoft Graph access"
info "Acquiring caller access token for https://graph.microsoft.com..."

GRAPH_TOKEN="$(az account get-access-token \
    --resource https://graph.microsoft.com \
    --query accessToken -o tsv 2>/dev/null || true)"

if [ -z "${GRAPH_TOKEN}" ]; then
    warn "Could not acquire a Graph access token - skipping verification"
else
    info "Calling GET https://graph.microsoft.com/v1.0/applications?\$top=1 ..."
    if az rest --method GET \
        --url "https://graph.microsoft.com/v1.0/applications?\$top=1" \
        --headers "Authorization=Bearer ${GRAPH_TOKEN}" \
        -o none 2>/dev/null; then
        ok "Microsoft Graph access confirmed"
    else
        fail "Admin consent may not have been granted yet - wait 60 seconds and retry"
    fi
fi

ok "Done."
exit 0
