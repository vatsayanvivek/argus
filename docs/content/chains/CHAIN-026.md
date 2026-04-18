# CHAIN-026 — Container registry takeover to supply chain poisoning

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Azure Container Registry has the admin account enabled, the registry is publicly accessible on the internet, and Microsoft Defender for Containers is not enabled. The admin credential is a static username/password pair that is frequently embedded in CI/CD pipelines, developer machines, and configuration files. An attacker who discovers this credential - through a leaked pipeline definition, a compromised developer workstation, or brute-force against the public endpoint - gains full push/pull access to all repositories. The attacker overwrites production image tags with backdoored variants. Without Defender for Containers, there is no runtime vulnerability scanning, no image integrity verification, and no behavioral detection when the malicious images execute in downstream clusters.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_012`](../rules/zt_wl_012.md) | Trigger |
| [`zt_wl_013`](../rules/zt_wl_013.md) | Trigger |
| [`zt_wl_021`](../rules/zt_wl_021.md) | Trigger |

## Attack walkthrough

### Step 1 — Discover the ACR admin credential from a leaked CI/CD pipeline, repository secret, or developer environment.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_wl_012`](../rules/zt_wl_012.md)  

> ACR admin account is enabled (adminUserEnabled=true); the credential is a static password that does not rotate automatically and is often stored in plaintext in build definitions.

**Attacker gain:** ACR admin username and password.


### Step 2 — Authenticate to the public ACR endpoint and enumerate all repositories and tags.

**Actor:** Attacker with admin credential  
**MITRE ATT&CK:** `T1595.002`  
**Enabled by:** [`zt_wl_013`](../rules/zt_wl_013.md)  

> ACR public network access is enabled with no IP firewall rules; docker login <registry>.azurecr.io succeeds from any IP. Catalog API lists all repositories.

**Attacker gain:** Full inventory of all container images and tags in the registry.


### Step 3 — Pull a production image, inject a backdoor, and push it back to the same tag.

**Actor:** Attacker with registry access  
**MITRE ATT&CK:** `T1195.002`  
**Enabled by:** [`zt_wl_012`](../rules/zt_wl_012.md)  

> docker pull, modify Dockerfile to add a reverse shell or crypto miner layer, docker push to overwrite the existing tag (e.g., :latest or :v2.1.0). No content trust or image signing is enforced.

**Attacker gain:** Malicious image sitting at a trusted production tag.


### Step 4 — Pull the tainted image on next deployment or pod restart.

**Actor:** Downstream AKS or App Service  
**MITRE ATT&CK:** `T1059`  
**Enabled by:** [`zt_wl_013`](../rules/zt_wl_013.md)  

> imagePullPolicy: Always or a rolling deployment triggers a pull of the compromised tag; the workload starts executing attacker code.

**Attacker gain:** Attacker code executing inside production workloads.


### Step 5 — Operate undetected because no runtime security monitoring exists.

**Actor:** Malicious container in production  
**MITRE ATT&CK:** `T1562.001`  
**Enabled by:** [`zt_wl_021`](../rules/zt_wl_021.md)  

> Defender for Containers is not enabled; no runtime behavioral analysis, no vulnerability assessment on running images, no anomalous process detection.

**Attacker gain:** Persistent undetected supply chain compromise across all workloads pulling from the registry.


## Blast radius

| | |
|---|---|
| Initial access | Leaked or brute-forced ACR admin credential over the public endpoint. |
| Lateral movement | Poisoned image → every workload pulling that tag → all environments (dev, staging, production). |
| Max privilege | Full registry write access + code execution in every consuming workload. |
| Data at risk | All data accessible to workloads pulling from ACR, Application secrets in environment variables, Managed identity tokens in running containers, Customer data processed by affected services |
| Services at risk | Azure Container Registry, AKS clusters, App Service containers, Azure Container Instances, Any CI/CD pipeline consuming images |
| Estimated scope | All workloads pulling from the compromised registry |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

