# CHAIN-001 — Internet-exposed VM to subscription takeover

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** High · **Logic:** `ANCHOR_PLUS_ONE` · **Anchor:** [`zt_net_001`](../rules/zt_net_001.md)

## Why this chain matters

An attacker scans Azure IP space, finds a VM with RDP or SSH open to 0.0.0.0/0, and walks into a login prompt. Because the VM runs with a System-Assigned Managed Identity that has been granted a privileged role at subscription scope, any code execution on that box yields a subscription-level Azure AD token through IMDS. From there the attacker uses the token to enumerate and impersonate other principals, create new credentials, and ultimately owns every resource in the subscription without ever touching a stolen password. This is the single most common 'one click to game over' pattern red teams exploit in Azure.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_001`](../rules/zt_net_001.md) | **Anchor** |
| [`zt_net_002`](../rules/zt_net_002.md) | Trigger |
| [`zt_wl_001`](../rules/zt_wl_001.md) | Trigger |
| [`zt_id_001`](../rules/zt_id_001.md) | Trigger |
| [`zt_id_008`](../rules/zt_id_008.md) | Trigger |

## Attack walkthrough

### Step 1 — Scan Azure public IP ranges for VMs exposing RDP/3389 or SSH/22 to the internet.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1595.001`  
**Enabled by:** [`zt_net_001`](../rules/zt_net_001.md)  

> Shodan / masscan against published Azure prefixes; NSG rule with SourceAddressPrefix='*' and DestinationPortRange='22' or '3389' is directly discoverable.

**Attacker gain:** Candidate list of reachable VMs; zero authentication required to reach the management port.


### Step 2 — Brute-force or password-spray the exposed management port against local admin accounts.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1110.003`  
**Enabled by:** [`zt_net_002`](../rules/zt_net_002.md)  

> Hydra/crowbar against RDP/SSH; local accounts have no tenant-level lockout, no Conditional Access, and no MFA.

**Attacker gain:** Interactive shell on the VM as a local administrator.


### Step 3 — Query the Instance Metadata Service (IMDS) to retrieve the VM's managed identity access token.

**Actor:** Attacker on VM  
**MITRE ATT&CK:** `T1552.005`  
**Enabled by:** [`zt_wl_001`](../rules/zt_wl_001.md)  

> curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H Metadata:true

**Attacker gain:** A valid ARM bearer token tied to the VM's System-Assigned identity.


### Step 4 — Enumerate the identity's role assignments and discover it holds Contributor or Owner at subscription scope.

**Actor:** Attacker with MI token  
**MITRE ATT&CK:** `T1087.004`  
**Enabled by:** [`zt_id_001`](../rules/zt_id_001.md)  

> GET /subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments?$filter=principalId eq '{miId}'

**Attacker gain:** Confirmation that the stolen token controls the entire subscription, not just the host VM.


### Step 5 — Create a new service principal with Owner rights and a long-lived client secret for durable access.

**Actor:** Attacker with subscription rights  
**MITRE ATT&CK:** `T1136.003`  
**Enabled by:** [`zt_id_008`](../rules/zt_id_008.md)  

> New-AzADServicePrincipal followed by New-AzRoleAssignment -RoleDefinitionName Owner -Scope /subscriptions/{sub}

**Attacker gain:** Persistent Owner-level credential that survives VM decommission and IR containment.


### Step 6 — Export Key Vault secrets, Storage keys, and SQL admin passwords subscription-wide.

**Actor:** Attacker with persistence  
**MITRE ATT&CK:** `T1555.006`  
**Enabled by:** [`zt_id_001`](../rules/zt_id_001.md)  

> az keyvault secret list/show across every vault; storage account keys listed via listKeys; SQL admin rotation via resource manager.

**Attacker gain:** Full subscription compromise: every data store, every credential, every workload.


## Blast radius

| | |
|---|---|
| Initial access | Single internet-exposed VM with management ports open to 0.0.0.0/0. |
| Lateral movement | IMDS token → ARM control plane → every resource in the subscription via managed identity RBAC. |
| Max privilege | Subscription Owner via System-Assigned Managed Identity inherited by the compromised VM. |
| Data at risk | Key Vault secrets, Storage account contents, SQL databases, Cosmos DB accounts, Disk snapshots |
| Services at risk | Compute, Storage, Key Vault, SQL, Resource Manager, Entra ID service principals |
| Estimated scope | 100% of the subscription |

## How the logic works

The chain fires when the **anchor** rule fires AND at least one of the other triggers fires. The anchor represents the initial foothold; the second rule amplifies it into a meaningful attack. Remediate the anchor to eliminate the entire chain.

