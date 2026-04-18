# CHAIN-024 — Cross-tenant trust abuse to data access

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Cross-tenant access settings use the default permissive configuration that trusts all external tenants, guest users are granted excessive directory permissions beyond the restricted default, and a Cosmos DB account is exposed with a public endpoint. An attacker from a foreign tenant receives or socially engineers a guest invitation. Because cross-tenant trust is default, the guest satisfies MFA requirements using their home tenant's MFA - the resource tenant never challenges them independently. The overpermissioned guest role grants directory read access and group membership that includes a role with Cosmos DB data plane access. The attacker reads production data from the publicly accessible Cosmos DB endpoint using the inherited credentials.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_017`](../rules/zt_id_017.md) | Trigger |
| [`zt_id_016`](../rules/zt_id_016.md) | Trigger |
| [`zt_data_011`](../rules/zt_data_011.md) | Trigger |

## Attack walkthrough

### Step 1 — Accept or socially engineer a guest invitation to the target tenant.

**Actor:** External attacker in a foreign tenant  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_017`](../rules/zt_id_017.md)  

> B2B invitation via email or direct link; default cross-tenant access settings allow inbound collaboration from all external tenants without restriction.

**Attacker gain:** Guest user object in the target tenant.


### Step 2 — Satisfy any Conditional Access MFA requirement using home-tenant MFA claim passthrough.

**Actor:** Guest user  
**MITRE ATT&CK:** `T1556.006`  
**Enabled by:** [`zt_id_017`](../rules/zt_id_017.md)  

> Cross-tenant trust settings accept MFA claims from the guest's home tenant (inbound trust redeemMfa=true by default); the resource tenant never issues its own MFA challenge.

**Attacker gain:** Full authenticated session in the resource tenant with MFA satisfied externally.


### Step 3 — Enumerate directory objects, group memberships, and application assignments.

**Actor:** Guest user with session  
**MITRE ATT&CK:** `T1087.004`  
**Enabled by:** [`zt_id_016`](../rules/zt_id_016.md)  

> Guest user permissions are set beyond the 'most restrictive' default; the guest can read all user profiles, group memberships, and enumerate applications via Microsoft Graph.

**Attacker gain:** Full directory enumeration and discovery of data-plane role assignments.


### Step 4 — Identify and join or leverage group memberships that grant Cosmos DB data plane access.

**Actor:** Guest user with directory knowledge  
**MITRE ATT&CK:** `T1069.003`  
**Enabled by:** [`zt_id_016`](../rules/zt_id_016.md)  

> Guest is already a member of or can request membership in a security group with Cosmos DB Data Reader or Data Contributor RBAC role assignment.

**Attacker gain:** Cosmos DB data plane credentials via inherited RBAC role.


### Step 5 — Connect to the public Cosmos DB endpoint and exfiltrate production data.

**Actor:** Guest user with data plane access  
**MITRE ATT&CK:** `T1530`  
**Enabled by:** [`zt_data_011`](../rules/zt_data_011.md)  

> Cosmos DB has publicNetworkAccess=Enabled and no IP firewall rules; data plane operations via REST API or SDK using the inherited RBAC token.

**Attacker gain:** Full read access to production data in Cosmos DB containers.


## Blast radius

| | |
|---|---|
| Initial access | Guest invitation from any external tenant. |
| Lateral movement | Guest session → directory enumeration → group-based RBAC inheritance → Cosmos DB data plane. |
| Max privilege | Cosmos DB Data Contributor (read/write on all containers) plus full directory read. |
| Data at risk | All Cosmos DB containers and documents, Directory user and group data, Application registration metadata |
| Services at risk | Azure Cosmos DB, Entra ID directory, Any service granting access via group membership |
| Estimated scope | Cosmos DB data + directory metadata |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

