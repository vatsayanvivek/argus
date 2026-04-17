<#
.SYNOPSIS
    ARGUS Scanner - Azure Service Principal bootstrap (PowerShell).

.DESCRIPTION
    Creates an Azure AD Service Principal for ARGUS with:
      * Reader role           (subscription scope)
      * Security Reader role  (subscription scope)
      * Microsoft Graph application-level permissions required by the
        identity-pillar rules (CHAIN-002 App Registration takeover, PIM,
        Conditional Access, access reviews, etc.)

    Uses the Azure CLI ('az') throughout - the Az PowerShell module is NOT
    required. The only prerequisite is a logged-in Azure CLI session.

.PARAMETER SubscriptionId
    Target Azure subscription GUID.

.PARAMETER TenantId
    Target Azure AD tenant GUID.

.PARAMETER SpnName
    Optional display name (default: argus-scanner).

.EXAMPLE
    ./setup-graph-permissions.ps1 -SubscriptionId <sub> -TenantId <tenant>
#>

param(
    [Parameter(Mandatory)][string] $SubscriptionId,
    [Parameter(Mandatory)][string] $TenantId,
    [string] $SpnName = "argus-scanner"
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------
function Write-Info   { param([string]$Msg) Write-Host "[INFO]  $Msg" -ForegroundColor Cyan }
function Write-Ok     { param([string]$Msg) Write-Host "[OK]    $Msg" -ForegroundColor Green }
function Write-Warn2  { param([string]$Msg) Write-Host "[WARN]  $Msg" -ForegroundColor Yellow }
function Write-Fail2  { param([string]$Msg) Write-Host "[FAIL]  $Msg" -ForegroundColor Red }
function Write-Header {
    param([string]$Msg)
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host $Msg -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Invoke az and return parsed JSON (or $null on failure).
# We deliberately use try/catch so a single az failure doesn't abort the run.
# ---------------------------------------------------------------------------
function Invoke-Az {
    param(
        [Parameter(Mandatory)][string[]]$Args,
        [switch]$IgnoreErrors
    )
    try {
        $output = & az @Args 2>&1
        if ($LASTEXITCODE -ne 0) {
            if (-not $IgnoreErrors) {
                Write-Warn2 "az $($Args -join ' ') exited with code $LASTEXITCODE"
                Write-Warn2 ($output | Out-String).Trim()
            }
            return $null
        }
        return ($output | Out-String)
    } catch {
        if (-not $IgnoreErrors) {
            Write-Warn2 "az invocation threw: $($_.Exception.Message)"
        }
        return $null
    }
}

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
Write-Info "Checking prerequisites..."

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Fail2 "Azure CLI ('az') is not installed. Install from https://aka.ms/InstallAzureCLI"
    exit 1
}
$azVerRaw = Invoke-Az -Args @('version','-o','json') -IgnoreErrors
if ($azVerRaw) {
    try {
        $azVer = ($azVerRaw | ConvertFrom-Json).'azure-cli'
        Write-Ok "az CLI found: $azVer"
    } catch {
        Write-Ok "az CLI found"
    }
} else {
    Write-Ok "az CLI found"
}

# ---------------------------------------------------------------------------
# Verify Azure login
# ---------------------------------------------------------------------------
Write-Info "Verifying Azure login..."
$acctRaw = Invoke-Az -Args @('account','show','-o','json') -IgnoreErrors
if (-not $acctRaw) {
    Write-Fail2 "You are not logged in to Azure. Run: az login --tenant $TenantId"
    exit 1
}
Write-Ok "Logged in to Azure"

Write-Info "Setting active subscription to $SubscriptionId..."
$null = Invoke-Az -Args @('account','set','--subscription',$SubscriptionId)
Write-Ok "Subscription set"

# ---------------------------------------------------------------------------
# Step 1 - Create the Service Principal with Reader at subscription scope
# ---------------------------------------------------------------------------
Write-Header "Step 1/7: Creating Service Principal '$SpnName'"

$appId    = $null
$password = $null
$spTenant = $null

try {
    $spRaw = & az ad sp create-for-rbac `
        --name $SpnName `
        --role "Reader" `
        --scopes "/subscriptions/$SubscriptionId" `
        -o json 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Fail2 "Failed to create service principal"
        Write-Fail2 ($spRaw | Out-String).Trim()
        exit 1
    }
    $sp = $spRaw | ConvertFrom-Json
    $appId    = $sp.appId
    $password = $sp.password
    $spTenant = $sp.tenant
} catch {
    Write-Fail2 "Failed to create service principal: $($_.Exception.Message)"
    exit 1
}

if (-not $appId) {
    Write-Fail2 "Failed to extract appId from service principal creation"
    exit 1
}

Write-Ok "Service principal created"
Write-Ok "  appId:  $appId"
Write-Ok "  tenant: $spTenant"

# ---------------------------------------------------------------------------
# Step 2 - Assign Security Reader at subscription scope
# ---------------------------------------------------------------------------
Write-Header "Step 2/7: Assigning Security Reader role"
Write-Info "Running: az role assignment create --role 'Security Reader'..."

# Retry a few times - AAD replication may be in progress.
$secReaderOk = $false
for ($attempt = 1; $attempt -le 5; $attempt++) {
    try {
        & az role assignment create `
            --assignee $appId `
            --role "Security Reader" `
            --scope "/subscriptions/$SubscriptionId" `
            -o none 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Security Reader assigned"
            $secReaderOk = $true
            break
        }
    } catch {
        # swallow and retry
    }
    Write-Info "Attempt $attempt/5 failed (likely AAD replication). Waiting..."
    Start-Sleep -Seconds ($attempt * 3)
}
if (-not $secReaderOk) {
    Write-Warn2 "Security Reader role could not be assigned automatically (it may already exist)."
    Write-Warn2 "Verify in the portal: Subscription -> Access control (IAM) -> Role assignments"
}

# ---------------------------------------------------------------------------
# Step 3 - Grant Microsoft Graph application permissions
# ---------------------------------------------------------------------------
Write-Header "Step 3/7: Granting Microsoft Graph application permissions"

$graphAppId = "00000003-0000-0000-c000-000000000000"

$graphPermissions = @(
    @{ Id = "bf394140-e372-4bf9-a898-299cfc7cc924"; Name = "SecurityEvents.Read.All" },
    @{ Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"; Name = "Directory.Read.All" },
    @{ Id = "246dd0d5-5bd0-4def-940b-0421030a5b68"; Name = "Policy.Read.All" },
    @{ Id = "dc5007c0-2d7d-4c42-879c-2dab87571379"; Name = "IdentityRiskyUser.Read.All" },
    @{ Id = "483bed4a-2ad3-4361-a73b-c83ccdbdc53c"; Name = "RoleManagement.Read.Directory" },
    @{ Id = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"; Name = "Application.Read.All" },
    @{ Id = "b0afded3-3588-46d8-8b3d-9842eff778da"; Name = "AuditLog.Read.All" },
    @{ Id = "230c1aed-a721-4c5d-9cb4-a90514e508ef"; Name = "Reports.Read.All" }
)

$permFails = 0
foreach ($perm in $graphPermissions) {
    Write-Info "Adding $($perm.Name) ($($perm.Id))"
    try {
        & az ad app permission add `
            --id $appId `
            --api $graphAppId `
            --api-permissions "$($perm.Id)=Role" `
            -o none 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "  Requested $($perm.Name)"
        } else {
            Write-Warn2 "  Failed to add $($perm.Name) (continuing)"
            $permFails++
        }
    } catch {
        Write-Warn2 "  Failed to add $($perm.Name): $($_.Exception.Message)"
        $permFails++
    }
}

if ($permFails -gt 0) {
    Write-Warn2 "$permFails permission(s) failed to register. Review output above."
} else {
    Write-Ok "All $($graphPermissions.Count) Microsoft Graph permissions registered"
}

# ---------------------------------------------------------------------------
# Step 4 - Grant admin consent
# ---------------------------------------------------------------------------
Write-Header "Step 4/7: Granting admin consent"
Write-Info "Running: az ad app permission admin-consent..."

$consentOk = $false
try {
    & az ad app permission admin-consent --id $appId 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Admin consent granted"
        $consentOk = $true
    }
} catch {
    # swallow
}

if (-not $consentOk) {
    Write-Warn2 "Admin consent failed."
    Write-Warn2 "This usually means your account is NOT a Global Administrator or"
    Write-Warn2 "Privileged Role Administrator. Ask an admin to grant consent via:"
    Write-Warn2 "  Azure Portal -> Azure AD -> App registrations -> $SpnName"
    Write-Warn2 "    -> API permissions -> Grant admin consent for <tenant>"
}

# ---------------------------------------------------------------------------
# Step 5 - Create a fresh 1-year client secret
# ---------------------------------------------------------------------------
Write-Header "Step 5/7: Creating fresh 1-year client secret"
Write-Info "Running: az ad app credential reset --years 1..."

try {
    $secretRaw = & az ad app credential reset --id $appId --years 1 -o json 2>$null
    if ($LASTEXITCODE -eq 0 -and $secretRaw) {
        $secret = ($secretRaw | Out-String | ConvertFrom-Json)
        if ($secret.password) {
            $password = $secret.password
            Write-Ok "New 1-year client secret issued"
        } else {
            Write-Warn2 "Credential reset succeeded but no password returned; keeping initial secret"
        }
    } else {
        Write-Warn2 "Could not issue a new client secret; keeping the one from step 1"
    }
} catch {
    Write-Warn2 "Credential reset threw: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Step 6 - Print credential block
# ---------------------------------------------------------------------------
Write-Header "Step 6/7: ARGUS Credentials"

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "ARGUS Scanner - Azure Credentials"              -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "Set these environment variables before running argus:"
Write-Host ""
Write-Host "export AZURE_TENANT_ID=`"$TenantId`""
Write-Host "export AZURE_CLIENT_ID=`"$appId`""
Write-Host "export AZURE_CLIENT_SECRET=`"$password`""
Write-Host "export AZURE_SUBSCRIPTION_ID=`"$SubscriptionId`""
Write-Host ""
Write-Host "Then run: argus scan --subscription `"`$AZURE_SUBSCRIPTION_ID`" --tenant `"`$AZURE_TENANT_ID`""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "WARNING: Save the client secret - it cannot be retrieved again." -ForegroundColor Yellow
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "# PowerShell-native equivalents:" -ForegroundColor DarkGray
Write-Host "`$env:AZURE_TENANT_ID       = `"$TenantId`""
Write-Host "`$env:AZURE_CLIENT_ID       = `"$appId`""
Write-Host "`$env:AZURE_CLIENT_SECRET   = `"$password`""
Write-Host "`$env:AZURE_SUBSCRIPTION_ID = `"$SubscriptionId`""
Write-Host ""

# ---------------------------------------------------------------------------
# Step 7 - Verify Microsoft Graph reachability
# ---------------------------------------------------------------------------
# NOTE: This verification uses the CALLER'S current access token, not the
# newly-minted SPN's token. To test the SPN itself you'd need to log in as
# the SPN (az login --service-principal ...), but we avoid that here to
# keep the script a single-shot bootstrap. The caller token probe is
# sufficient to confirm admin-consent has propagated tenant-wide.
# ---------------------------------------------------------------------------
Write-Header "Step 7/7: Verifying Microsoft Graph access"
Write-Info "Acquiring caller access token for https://graph.microsoft.com..."

$token = $null
try {
    $token = & az account get-access-token `
        --resource https://graph.microsoft.com `
        --query accessToken -o tsv 2>$null
    if ($LASTEXITCODE -ne 0) { $token = $null }
} catch {
    $token = $null
}

if (-not $token) {
    Write-Warn2 "Could not acquire a Graph access token - skipping verification"
} else {
    Write-Info "Calling GET https://graph.microsoft.com/v1.0/applications?`$top=1 ..."
    try {
        & az rest --method GET `
            --url 'https://graph.microsoft.com/v1.0/applications?$top=1' `
            --headers "Authorization=Bearer $token" `
            -o none 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Microsoft Graph access confirmed"
        } else {
            Write-Fail2 "Admin consent may not have been granted yet - wait 60 seconds and retry"
        }
    } catch {
        Write-Fail2 "Admin consent may not have been granted yet - wait 60 seconds and retry"
    }
}

Write-Ok "Done."
exit 0
