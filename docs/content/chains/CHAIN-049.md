# CHAIN-049 — AKS full stack compromise via public registry and layered misconfigurations

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** High · **Logic:** `ANCHOR_PLUS_ONE` · **Anchor:** [`zt_wl_013`](../rules/zt_wl_013.md)

## Why this chain matters

This is the Kubernetes nightmare scenario where every layer of the stack is misconfigured simultaneously. The Azure Container Registry allows public (anonymous) access, serving as the anchor finding that enables supply-chain injection. On top of that, one or more of the following conditions amplify the blast radius: ACR admin account is enabled (providing a static, non-rotatable credential), AKS has no network policy enforcement (pods can communicate freely across namespaces), Azure RBAC for Kubernetes is not enabled (legacy kubeconfig grants cluster-admin), pod security standards are not enforced (privileged pods can escape to the node), and Microsoft Defender for Containers is not enabled (runtime threats go undetected). An attacker who pushes a malicious image to the public ACR can escalate through whichever combination of these weaknesses exists, ultimately achieving cluster-admin, node-level access, and control-plane compromise of the entire AKS environment.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_013`](../rules/zt_wl_013.md) | **Anchor** |
| [`zt_wl_012`](../rules/zt_wl_012.md) | Trigger |
| [`zt_wl_014`](../rules/zt_wl_014.md) | Trigger |
| [`zt_wl_015`](../rules/zt_wl_015.md) | Trigger |
| [`zt_wl_016`](../rules/zt_wl_016.md) | Trigger |
| [`zt_wl_021`](../rules/zt_wl_021.md) | Trigger |

## Attack walkthrough

### Step 1 — Push a malicious container image to the publicly accessible ACR, optionally using the admin credential.

**Actor:** Supply-chain attacker  
**MITRE ATT&CK:** `T1195.002`  
**Enabled by:** [`zt_wl_013`](../rules/zt_wl_013.md)  

> ACR is configured with publicNetworkAccess=Enabled and anonymousPullEnabled=true (zt_wl_013). If the admin account is enabled (zt_wl_012), the attacker may also use the static admin username/password (available via az acr credential show) to push. Image tag 'latest' or a version tag is overwritten with a trojanised image.

**Attacker gain:** Malicious image placed at a trusted tag in the production registry.


### Step 2 — Pull and deploy the tainted image as a privileged pod due to missing pod security enforcement.

**Actor:** AKS cluster (automated pull)  
**MITRE ATT&CK:** `T1610`  
**Enabled by:** [`zt_wl_016`](../rules/zt_wl_016.md)  

> No pod security standards (zt_wl_016) means the malicious image's pod spec can request privileged=true, hostPID=true, hostNetwork=true, and mount hostPath=/. The Kubernetes admission controller does not reject the escalated pod spec.

**Attacker gain:** Malicious container running with full host privileges inside the AKS cluster.


### Step 3 — Escape the container to the underlying node and steal the kubelet's managed identity token.

**Actor:** Attacker in privileged pod  
**MITRE ATT&CK:** `T1611`  
**Enabled by:** [`zt_wl_016`](../rules/zt_wl_016.md)  

> Mount the host filesystem via hostPath=/, access /var/lib/kubelet and the container runtime socket. Query IMDS at 169.254.169.254 from the host network namespace to obtain the node's managed identity token.

**Attacker gain:** Root access on the AKS node and a valid ARM token for the node's managed identity.


### Step 4 — Move laterally across namespaces exploiting the absence of network policies.

**Actor:** Attacker on node  
**MITRE ATT&CK:** `T1210`  
**Enabled by:** [`zt_wl_014`](../rules/zt_wl_014.md)  

> No Kubernetes network policies (zt_wl_014) means all pod-to-pod traffic is allowed across every namespace. The attacker's pod can reach kube-system components, monitoring agents, and every application pod's exposed ports directly.

**Attacker gain:** Unrestricted network access to every pod and service in every namespace of the cluster.


### Step 5 — Obtain cluster-admin privileges via legacy kubeconfig because Azure RBAC for Kubernetes is disabled.

**Actor:** Attacker with cluster access  
**MITRE ATT&CK:** `T1078.001`  
**Enabled by:** [`zt_wl_015`](../rules/zt_wl_015.md)  

> Without Azure RBAC for AKS (zt_wl_015), the cluster uses legacy Kubernetes RBAC. The attacker extracts the cluster-admin kubeconfig from the compromised node or from the AKS management API using the stolen managed identity token (az aks get-credentials --admin).

**Attacker gain:** Full cluster-admin Kubernetes API access - can create, modify, and delete any resource in any namespace.


### Step 6 — Operate with impunity as Defender for Containers is not monitoring runtime threats.

**Actor:** Attacker with cluster-admin  
**MITRE ATT&CK:** `T1562.001`  
**Enabled by:** [`zt_wl_021`](../rules/zt_wl_021.md)  

> Microsoft Defender for Containers (zt_wl_021) is not enabled, so runtime threat detections (crypto mining, reverse shells, suspicious exec into containers, known malicious images) are not generated. The attacker's activities produce no security alerts.

**Attacker gain:** Complete AKS stack compromise with no runtime detection: registry to pod to node to cluster-admin, entirely unmonitored.


## Blast radius

| | |
|---|---|
| Initial access | Publicly accessible Azure Container Registry allowing anonymous image push. |
| Lateral movement | Container → privileged pod → node → cross-namespace (no network policy) → cluster-admin (no Azure RBAC). |
| Max privilege | cluster-admin on AKS + node-level managed identity on ARM + potential access to all downstream services the cluster identity can reach. |
| Data at risk | All application data accessible to cluster workloads, Kubernetes Secrets (including TLS certs and service credentials), Persistent Volumes and their contents, Container registry images (IP, source code) |
| Services at risk | AKS, ACR, Resource Manager (via node identity), All services consumed by cluster workloads |
| Estimated scope | 100% of the AKS cluster and its resource group |

## How the logic works

The chain fires when the **anchor** rule fires AND at least one of the other triggers fires. The anchor represents the initial foothold; the second rule amplifies it into a meaningful attack. Remediate the anchor to eliminate the entire chain.

