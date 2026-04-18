# CHAIN-028 — Key Vault silent breach and purge

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A Key Vault has purge protection disabled, its diagnostic logging is not configured, and stale service principal credentials exist in the tenant that still have Key Vault access policies or RBAC roles. An attacker discovers an old, forgotten service principal credential - from a decommissioned application, a developer's notes, or a leaked CI/CD configuration. The stale credential still authenticates successfully and retains its Key Vault access. The attacker reads all secrets, keys, and certificates, then soft-deletes and immediately purges the vault. Because diagnostic logging was never enabled, there is no audit trail of who accessed the vault or when the purge occurred. The combination of no purge protection, no logging, and stale credentials creates an unrecoverable, uninvestigable cryptographic material loss.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_014`](../rules/zt_data_014.md) | Trigger |
| [`zt_vis_014`](../rules/zt_vis_014.md) | Trigger |
| [`zt_id_024`](../rules/zt_id_024.md) | Trigger |

## Attack walkthrough

### Step 1 — Discover a stale service principal credential that was never rotated or decommissioned.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_id_024`](../rules/zt_id_024.md)  

> Service principal has passwordCredentials with endDateTime far in the future or already expired but still functional (credential not removed, just expired); found in old repo, wiki, or config file.

**Attacker gain:** Valid service principal credential with Key Vault permissions.


### Step 2 — Authenticate as the service principal and enumerate accessible Key Vault resources.

**Actor:** Attacker with SP credential  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_024`](../rules/zt_id_024.md)  

> az login --service-principal; then az keyvault list to find vaults where the SP has access policies or RBAC data-plane roles.

**Attacker gain:** List of Key Vaults accessible to the compromised service principal.


### Step 3 — Read all secrets, keys, and certificates from the vault.

**Actor:** Attacker with vault access  
**MITRE ATT&CK:** `T1555`  
**Enabled by:** [`zt_vis_014`](../rules/zt_vis_014.md)  

> az keyvault secret list / az keyvault secret show for each secret; same for keys and certificates. All cryptographic material and connection strings exfiltrated.

**Attacker gain:** Complete copy of all secrets, keys, and certificates - database passwords, API keys, TLS certificates, encryption keys.


### Step 4 — Soft-delete the vault and immediately purge it to destroy evidence.

**Actor:** Attacker covering tracks  
**MITRE ATT&CK:** `T1485`  
**Enabled by:** [`zt_data_014`](../rules/zt_data_014.md)  

> az keyvault delete followed by az keyvault purge; purge protection is disabled (enablePurgeProtection=false), so purge succeeds immediately instead of enforcing the retention period.

**Attacker gain:** Vault and all its contents permanently destroyed with no recovery possible.


### Step 5 — Discover the vault is gone and find no diagnostic logs to investigate.

**Actor:** Defenders responding  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_vis_014`](../rules/zt_vis_014.md)  

> No diagnostic settings were configured on the vault (diagnosticSettings is empty); AuditEvent logs were never sent to Log Analytics, Storage, or Event Hub. The Azure Activity Log shows the delete but not the data-plane reads.

**Attacker gain:** Investigation is impossible - no record of what was read, by whom, or when. Incident response is blind.


## Blast radius

| | |
|---|---|
| Initial access | Stale service principal credential with Key Vault access. |
| Lateral movement | Stolen secrets enable lateral movement to every service whose credentials were in the vault. |
| Max privilege | Full Key Vault data plane access + ability to purge. |
| Data at risk | All secrets in the vault, All encryption keys, All TLS certificates, All systems whose credentials were stored in the vault |
| Services at risk | Azure Key Vault, Every service whose secrets were in the vault (databases, APIs, storage accounts, third-party services), Encryption-dependent workloads |
| Estimated scope | The vault contents + every downstream system authenticated by vault secrets |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

