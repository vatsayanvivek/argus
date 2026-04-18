# CHAIN-046 — Function App compromise to internal network pivot

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

An Azure Function App runs on an outdated runtime version with known CVEs, creating a remotely exploitable entry point. Rather than using a managed identity for authentication to downstream services, the Function stores connection strings and service principal credentials in application settings (environment variables), making them trivially extractable after code execution is achieved. The Function is VNet-integrated into a subnet that has no Network Security Group, meaning once the attacker has the Function's network context, they can reach any host on the subnet - and any peered VNet - without any network-layer access control. The combination turns a single serverless function exploit into a full internal network compromise.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_017`](../rules/zt_wl_017.md) | Trigger |
| [`zt_id_025`](../rules/zt_id_025.md) | Trigger |
| [`zt_net_019`](../rules/zt_net_019.md) | Trigger |

## Attack walkthrough

### Step 1 — Exploit a known vulnerability in the outdated Function App runtime to achieve remote code execution.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_wl_017`](../rules/zt_wl_017.md)  

> The Function runs on a runtime version with published CVEs (e.g., Node.js <18 LTS, Python 3.8 EOL, .NET 6 out of support). Attacker sends a crafted HTTP request that triggers the vulnerability in the runtime or a dependent package.

**Attacker gain:** Arbitrary code execution within the Function App's sandbox context.


### Step 2 — Dump application settings to extract stored credentials and connection strings.

**Actor:** Attacker with code execution  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_id_025`](../rules/zt_id_025.md)  

> Read environment variables via process.env (Node), os.environ (Python), or Environment.GetEnvironmentVariables() (.NET). Application settings contain SQL connection strings, storage account keys, and service principal clientId/clientSecret pairs because managed identity is not used.

**Attacker gain:** Plaintext credentials for downstream Azure services: SQL, Storage, Key Vault, and potentially a service principal with broad RBAC.


### Step 3 — Use the service principal credentials to authenticate to Azure Resource Manager and enumerate the environment.

**Actor:** Attacker with stolen credentials  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_025`](../rules/zt_id_025.md)  

> az login --service-principal -u {clientId} -p {clientSecret} --tenant {tenantId}; az resource list; the SP typically has Contributor at the resource group level or broader.

**Attacker gain:** Authenticated ARM access with whatever RBAC the stolen service principal holds.


### Step 4 — Pivot from the Function's VNet-integrated subnet to internal hosts on the unprotected subnet and peered VNets.

**Actor:** Attacker with network access  
**MITRE ATT&CK:** `T1046`  
**Enabled by:** [`zt_net_019`](../rules/zt_net_019.md)  

> The Function's outbound traffic originates from the integrated subnet which has no NSG. Scan internal IP ranges with nmap/portscan from within the Function execution context; reach databases, VMs, and internal APIs on RFC1918 addresses with zero network filtering.

**Attacker gain:** Network-level access to all hosts on the subnet and any peered VNets, bypassing what should be the network segmentation boundary.


### Step 5 — Access internal databases and services using the stolen connection strings from the Function's environment.

**Actor:** Attacker on internal network  
**MITRE ATT&CK:** `T1021.002`  
**Enabled by:** [`zt_net_019`](../rules/zt_net_019.md)  

> Connect to SQL databases, Redis caches, and storage accounts using the connection strings harvested in Step 2; these services trust connections from the VNet and the credentials are valid.

**Attacker gain:** Full access to internal data stores and services that were assumed to be protected by network isolation.


## Blast radius

| | |
|---|---|
| Initial access | Publicly accessible Function App running an outdated, vulnerable runtime version. |
| Lateral movement | VNet integration with no NSG allows unrestricted lateral movement to all hosts on the subnet and peered networks. |
| Max privilege | Service principal credentials from the Function's environment, plus network access to all internal hosts. |
| Data at risk | Function App application secrets, SQL databases reachable from the subnet, Storage accounts with harvested keys, Internal APIs and services on peered VNets |
| Services at risk | Azure Functions, SQL Database, Storage Accounts, Redis Cache, Any service on the integrated VNet |
| Estimated scope | The integrated subnet and all peered VNets |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

