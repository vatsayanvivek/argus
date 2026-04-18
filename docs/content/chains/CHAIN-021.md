# CHAIN-021 — Public registry AKS public endpoint to supply chain

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

An Azure Container Registry allows anonymous pull, an AKS cluster pulling from it has a public API server, and pods are allowed to run privileged. An attacker with anonymous push access (via a weak ACR policy or a compromised CI token) replaces a trusted image tag with a malicious one; the next cluster deployment pulls it over the public network, runs it privileged, and the supply-chain foothold instantly becomes cluster-admin.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_002`](../rules/zt_wl_002.md) | Trigger |
| [`zt_wl_003`](../rules/zt_wl_003.md) | Trigger |
| [`zt_wl_007`](../rules/zt_wl_007.md) | Trigger |

## Attack walkthrough

### Step 1 — Push a malicious image to a tag consumed by production workloads.

**Actor:** Supply-chain attacker  
**MITRE ATT&CK:** `T1195.002`  
**Enabled by:** [`zt_wl_002`](../rules/zt_wl_002.md)  

> ACR allows anonymous pull and has weak or missing push ACLs, or a compromised CI token is reused; image tag 'latest' is overwritten.

**Attacker gain:** Malicious image sitting at a trusted tag location.


### Step 2 — Pulls the tainted image on next pod start and schedules it as a privileged pod.

**Actor:** AKS cluster  
**MITRE ATT&CK:** `T1059`  
**Enabled by:** [`zt_wl_003`](../rules/zt_wl_003.md)  

> Public API server and public registry in the data path; no image signature verification (e.g., ratify/notary) enforced.

**Attacker gain:** Malicious container running inside the cluster.


### Step 3 — Escape to the node via privileged/hostPath mount and steal the kubelet managed identity.

**Actor:** Attacker inside container  
**MITRE ATT&CK:** `T1611`  
**Enabled by:** [`zt_wl_007`](../rules/zt_wl_007.md)  

> Pod spec permits privileged=true; mount /var/run/docker.sock or hostPath=/ to break out.

**Attacker gain:** Root on the node and access to the cluster identity token.


### Step 4 — Pivot to ARM with the kubelet identity.

**Actor:** Attacker on node  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_wl_007`](../rules/zt_wl_007.md)  

> IMDS token for the managed identity is used against Resource Manager; deployment control extends across the AKS resource group.

**Attacker gain:** Cluster + resource group compromise and a durable supply-chain vector.


## Blast radius

| | |
|---|---|
| Initial access | Tainted image in a permissive or anonymously-writable registry. |
| Lateral movement | Container → privileged pod → node → ARM via managed identity. |
| Max privilege | cluster-admin + whatever the node identity holds on the resource group. |
| Data at risk | All cluster workloads, All data cluster identities can reach, Source code in mounted volumes |
| Services at risk | AKS, ACR, Resource Manager, Downstream services consuming cluster output |
| Estimated scope | Cluster + its resource group |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

