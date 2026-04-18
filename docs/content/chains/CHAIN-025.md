# CHAIN-025 — AKS cluster full compromise

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

An AKS cluster has no Kubernetes network policies enforced, uses legacy Kubernetes RBAC instead of Azure RBAC for Kubernetes authorization, and has no pod security standards applied. An attacker who gains code execution in any pod - through a vulnerable application, SSRF, or compromised dependency - can reach every other pod and service in the cluster because no network segmentation exists. The attacker then escalates to cluster-admin through the legacy Kubernetes RBAC system, which often has overly permissive default ClusterRoleBindings. With cluster-admin, the attacker deploys privileged pods with hostPath mounts to escape to the node, access the kubelet identity, and pivot to Azure Resource Manager.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_014`](../rules/zt_wl_014.md) | Trigger |
| [`zt_wl_015`](../rules/zt_wl_015.md) | Trigger |
| [`zt_wl_016`](../rules/zt_wl_016.md) | Trigger |

## Attack walkthrough

### Step 1 — Perform network reconnaissance across all namespaces from within a compromised pod.

**Actor:** Attacker with pod-level access  
**MITRE ATT&CK:** `T1046`  
**Enabled by:** [`zt_wl_014`](../rules/zt_wl_014.md)  

> No Kubernetes NetworkPolicy objects exist; default behavior is allow-all ingress and egress across all namespaces. Pod can reach kube-dns, kube-apiserver, and all service ClusterIPs.

**Attacker gain:** Full network map of all services, pods, and endpoints in the cluster.


### Step 2 — Reach and exploit adjacent pods hosting different microservices.

**Actor:** Attacker in compromised pod  
**MITRE ATT&CK:** `T1021`  
**Enabled by:** [`zt_wl_014`](../rules/zt_wl_014.md)  

> No east-west traffic restrictions; attacker connects to database pods, cache instances, and internal APIs directly via cluster networking.

**Attacker gain:** Access to internal services that should only be reachable by specific workloads.


### Step 3 — Escalate to cluster-admin by exploiting legacy Kubernetes RBAC misconfigurations.

**Actor:** Attacker with lateral movement  
**MITRE ATT&CK:** `T1078.001`  
**Enabled by:** [`zt_wl_015`](../rules/zt_wl_015.md)  

> Azure RBAC for Kubernetes is not enabled; local Kubernetes RBAC has default ClusterRoleBindings granting excessive permissions to service accounts. kubectl auth can-i --list reveals cluster-admin equivalent permissions.

**Attacker gain:** cluster-admin role binding - full control over all Kubernetes resources.


### Step 4 — Deploy a privileged pod with hostPath mount to escape the container boundary.

**Actor:** Attacker with cluster-admin  
**MITRE ATT&CK:** `T1611`  
**Enabled by:** [`zt_wl_016`](../rules/zt_wl_016.md)  

> No pod security admission (no PodSecurity standards or OPA/Gatekeeper policies); attacker creates a pod with securityContext.privileged=true and hostPath=/ to mount the node filesystem.

**Attacker gain:** Root access on the underlying AKS node.


### Step 5 — Steal the kubelet managed identity token from IMDS and pivot to Azure Resource Manager.

**Actor:** Attacker on AKS node  
**MITRE ATT&CK:** `T1552.005`  
**Enabled by:** [`zt_wl_016`](../rules/zt_wl_016.md)  

> curl http://169.254.169.254/metadata/identity/oauth2/token on the node returns an ARM token for the kubelet identity; this identity typically has Contributor on the MC_ resource group.

**Attacker gain:** Azure ARM access with the kubelet managed identity - control over the AKS infrastructure resource group.


## Blast radius

| | |
|---|---|
| Initial access | Code execution in any pod (vulnerable app, supply chain, SSRF). |
| Lateral movement | Compromised pod → all cluster pods → cluster-admin → node escape → Azure ARM. |
| Max privilege | cluster-admin + kubelet managed identity (typically Contributor on the MC_ resource group). |
| Data at risk | All data in all cluster workloads, Kubernetes secrets, Managed identity tokens, ConfigMaps with credentials, Persistent volumes |
| Services at risk | AKS cluster, All microservices, Azure Resource Manager (MC_ resource group), Any Azure service the kubelet identity can reach |
| Estimated scope | Entire AKS cluster + its infrastructure resource group |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

