# CHAIN-018 — No WAF no DDoS no vuln assessment to app breach

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

A public-facing application has no WAF in front of it, no DDoS Standard protection on its public IP, and no vulnerability assessment runs against its images or code. Attackers hit it with off-the-shelf web-app exploits, take it down with volumetric traffic on demand, and there is no upstream control that would have caught or absorbed any of it.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_008`](../rules/zt_net_008.md) | Trigger |
| [`zt_net_007`](../rules/zt_net_007.md) | Trigger |
| [`zt_wl_006`](../rules/zt_wl_006.md) | Trigger |

## Attack walkthrough

### Step 1 — Scan the application with automated vulnerability tooling.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1595.002`  
**Enabled by:** [`zt_wl_006`](../rules/zt_wl_006.md)  

> Burp / ZAP against the public hostname; known CVEs in dependencies are identified because vuln assessment never caught them pre-deploy.

**Attacker gain:** List of exploitable vulnerabilities in the running application.


### Step 2 — Exploit SQL injection / deserialization / SSRF without WAF interference.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_net_008`](../rules/zt_net_008.md)  

> No Application Gateway WAF or Front Door WAF fronts the app; raw request reaches the origin.

**Attacker gain:** Code execution or direct database access through the web tier.


### Step 3 — Follow up with a volumetric DDoS as cover for the intrusion.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1498`  
**Enabled by:** [`zt_net_007`](../rules/zt_net_007.md)  

> DDoS Network Protection is Basic (free tier), no Standard plan; public IP absorbs no mitigation.

**Attacker gain:** Defenders distracted by availability crisis during data theft.


## Blast radius

| | |
|---|---|
| Initial access | Direct internet traffic to the application endpoint. |
| Lateral movement | Application foothold → backend services (DB, queues, caches). |
| Max privilege | Application service account + anything it can reach. |
| Data at risk | Customer data in the application database, Uploaded files, Session tokens |
| Services at risk | App Service / AKS ingress, Backend databases, Downstream APIs |
| Estimated scope | The application and its backing stores |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

