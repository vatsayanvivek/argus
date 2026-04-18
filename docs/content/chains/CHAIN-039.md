# CHAIN-039 — AKS Secrets Exposure to Data Breach

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

AKS clusters are not using the Azure Key Vault CSI driver, meaning application secrets - database passwords, API keys, connection strings - are stored as Kubernetes Secrets (base64-encoded, not encrypted at the application layer) or injected directly as environment variables in pod specs. No Kubernetes network policy restricts pod-to-pod traffic, and the Key Vault that would be the correct secrets store has purge protection disabled. An attacker who gains access to any pod in the cluster - via an application vulnerability, a compromised container image, or kubectl exec through a stolen kubeconfig - can read every secret in the namespace from environment variables or the Kubernetes API. Those secrets unlock the Key Vault, where the attacker can read all remaining secrets and, critically, permanently delete (purge) them to destroy evidence or cause maximum damage.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_022`](../rules/zt_wl_022.md) | Trigger |
| [`zt_wl_014`](../rules/zt_wl_014.md) | Trigger |
| [`zt_data_014`](../rules/zt_data_014.md) | Trigger |

## Attack walkthrough

### Step 1 — Read secrets from environment variables and Kubernetes Secret objects in the pod's namespace.

**Actor:** Attacker with pod access  
**MITRE ATT&CK:** `T1552.007`  
**Enabled by:** [`zt_wl_022`](../rules/zt_wl_022.md)  

> printenv reveals DATABASE_PASSWORD, API_KEY, CONN_STRING injected via env: valueFrom: secretKeyRef; kubectl get secrets -o yaml returns base64-encoded values trivially decoded.

**Attacker gain:** Plaintext application secrets including database credentials, API keys, and Key Vault access credentials.


### Step 2 — Move laterally to other pods and namespaces due to absent network policies.

**Actor:** Attacker inside cluster  
**MITRE ATT&CK:** `T1046`  
**Enabled by:** [`zt_wl_014`](../rules/zt_wl_014.md)  

> No NetworkPolicy objects defined; all pods can communicate with all other pods on any port. Attacker scans the cluster CIDR (10.244.0.0/16) for services and databases.

**Attacker gain:** Access to every service in the cluster - databases, caches, internal APIs - from any compromised pod.


### Step 3 — Authenticate to Azure Key Vault using the service principal credentials or managed identity token found in environment variables.

**Actor:** Attacker with harvested credentials  
**MITRE ATT&CK:** `T1555.006`  
**Enabled by:** [`zt_wl_022`](../rules/zt_wl_022.md)  

> az keyvault secret list --vault-name {name} using AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID harvested from pod env vars; or use the pod's workload identity token.

**Attacker gain:** Read access to all secrets in the Key Vault - TLS certificates, encryption keys, additional service credentials.


### Step 4 — Exfiltrate all Key Vault secrets and then purge the vault to destroy evidence and maximize impact.

**Actor:** Attacker with Key Vault access  
**MITRE ATT&CK:** `T1485`  
**Enabled by:** [`zt_data_014`](../rules/zt_data_014.md)  

> az keyvault secret download for each secret; then az keyvault delete followed by az keyvault purge. Purge protection is disabled, so the soft-deleted vault is permanently destroyed.

**Attacker gain:** All secrets exfiltrated to attacker infrastructure; Key Vault and all its contents permanently destroyed with no recovery possible.


### Step 5 — Use exfiltrated database credentials and API keys to access production data stores directly from outside the cluster.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1530`  
**Enabled by:** [`zt_wl_022`](../rules/zt_wl_022.md)  

> SQL connection strings, Cosmos DB keys, and Storage account keys from the vault used to connect to data stores over their public or private endpoints.

**Attacker gain:** Full production data breach - customer records, financial data, PII - with the Key Vault destroyed to hamper incident response.


## Blast radius

| | |
|---|---|
| Initial access | Any pod in the AKS cluster via application vulnerability, supply chain, or stolen kubeconfig. |
| Lateral movement | Pod → all namespaces (no network policy) → Key Vault → external data stores. |
| Max privilege | Key Vault data-plane access with purge capability plus direct database access via harvested credentials. |
| Data at risk | All Kubernetes Secrets in the cluster, All Key Vault secrets, Production databases, Storage account contents, TLS private keys |
| Services at risk | AKS, Key Vault, SQL Database, Cosmos DB, Storage Accounts, Any service whose credentials were in the vault |
| Estimated scope | Cluster + all backend data stores referenced by application secrets |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

