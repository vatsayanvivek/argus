# CHAIN-006 — AKS public endpoint privileged containers to takeover

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

An AKS cluster has its API server reachable over the internet, pods are permitted to run as privileged or with hostPath mounts, and the cluster's managed identity can fetch secrets from a Key Vault whose soft-delete/purge protection is disabled. An attacker who hijacks the kubeconfig (or exploits an unauthenticated API server endpoint) escapes a container, accesses the node filesystem, pulls the cluster identity token, and drains the Key Vault - then purges the vault to destroy forensic evidence.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_003`](../rules/zt_wl_003.md) | Trigger |
| [`zt_wl_007`](../rules/zt_wl_007.md) | Trigger |
| [`zt_data_004`](../rules/zt_data_004.md) | Trigger |

## Attack walkthrough

### Step 1 — Reach the AKS API server from the internet and exploit weak authentication or a known CVE.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_wl_003`](../rules/zt_wl_003.md)  

> Public FQDN *.hcp.{region}.azmk8s.io reachable from anywhere; combined with aged kubeconfig or misconfigured OIDC, the attacker obtains cluster-admin.

**Attacker gain:** kubectl access to the cluster.


### Step 2 — Deploy a privileged pod with hostPath=/ and run as root to break out to the node.

**Actor:** Attacker with kubectl  
**MITRE ATT&CK:** `T1611`  
**Enabled by:** [`zt_wl_007`](../rules/zt_wl_007.md)  

> kubectl apply of a pod spec with securityContext.privileged=true and volumes[].hostPath.path=/ - PodSecurity admission is set to baseline/privileged.

**Attacker gain:** Root shell on the underlying AKS node.


### Step 3 — Query IMDS from the node and obtain the kubelet's managed identity token.

**Actor:** Attacker on node  
**MITRE ATT&CK:** `T1552.005`  
**Enabled by:** [`zt_wl_007`](../rules/zt_wl_007.md)  

> curl http://169.254.169.254/metadata/identity/oauth2/token?resource=https://vault.azure.net - node identity has Key Vault Reader or Secrets User.

**Attacker gain:** Bearer token for Azure Key Vault scoped to the cluster identity.


### Step 4 — Exfiltrate every secret from the associated Key Vault.

**Actor:** Attacker with KV token  
**MITRE ATT&CK:** `T1555.006`  
**Enabled by:** [`zt_data_004`](../rules/zt_data_004.md)  

> az keyvault secret list + per-secret show using the managed identity token; database credentials, API keys, signing certs all disclosed.

**Attacker gain:** Downstream credential reuse across SQL, service principals, and partner APIs.


### Step 5 — Purge the Key Vault to destroy forensic evidence.

**Actor:** Attacker with KV admin  
**MITRE ATT&CK:** `T1485`  
**Enabled by:** [`zt_data_004`](../rules/zt_data_004.md)  

> Because soft-delete / purge protection is disabled, az keyvault delete followed by az keyvault purge succeeds. Secret version history is unrecoverable.

**Attacker gain:** Destruction of audit trail and rotation baseline, impeding recovery.


## Blast radius

| | |
|---|---|
| Initial access | Public AKS API server. |
| Lateral movement | Container → privileged pod → node → Azure IMDS → Key Vault. |
| Max privilege | cluster-admin on AKS + Key Vault secret reader/purger on the associated vault. |
| Data at risk | Cluster workloads, Node filesystems, All Key Vault secrets, Downstream services whose credentials were in the vault |
| Services at risk | AKS, Key Vault, Any service whose credentials were in the vault |
| Estimated scope | Cluster + associated vault + every downstream service whose creds were in the vault |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

