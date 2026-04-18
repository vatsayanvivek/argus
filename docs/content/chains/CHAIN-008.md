# CHAIN-008 — Defender disabled open ports to blind execution

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** High · **Logic:** `ANCHOR_PLUS_ONE` · **Anchor:** [`zt_vis_003`](../rules/zt_vis_003.md)

## Why this chain matters

Microsoft Defender for Cloud Servers plan is turned off, management ports are open to the internet, and activity logs are not shipped to a SIEM. An attacker brute-forces or exploits the exposed port, executes payloads on the VM, and neither the host-based Defender sensor nor the control-plane audit trail reports anything. The environment becomes a blind spot: compromise happens in full darkness.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_vis_003`](../rules/zt_vis_003.md) | **Anchor** |
| [`zt_net_001`](../rules/zt_net_001.md) | Trigger |
| [`zt_net_002`](../rules/zt_net_002.md) | Trigger |
| [`zt_vis_002`](../rules/zt_vis_002.md) | Trigger |

## Attack walkthrough

### Step 1 — Locate a VM exposing SSH/RDP/WinRM to the internet.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1595.001`  
**Enabled by:** [`zt_net_001`](../rules/zt_net_001.md)  

> Shodan / internet-wide TLS banner scan; NSG permits 0.0.0.0/0 on port 22 or 3389.

**Attacker gain:** Reachable compromise target.


### Step 2 — Exploit or brute-force the exposed service to gain interactive access.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1110.003`  
**Enabled by:** [`zt_net_002`](../rules/zt_net_002.md)  

> Credential spray against local accounts; or exploitation of unpatched SSH/RDP CVEs.

**Attacker gain:** Shell on the VM as a local user.


### Step 3 — Execute tooling with zero host-level detection.

**Actor:** Attacker on VM  
**MITRE ATT&CK:** `T1562.001`  
**Enabled by:** [`zt_vis_003`](../rules/zt_vis_003.md)  

> Defender for Servers plan is Free/off: no MDE sensor, no file behaviour monitoring, no EDR telemetry generated.

**Attacker gain:** Unobserved execution of discovery, credential dumping, and persistence tools.


### Step 4 — Operate without control-plane telemetry either - Activity Log is not exported to a SIEM.

**Actor:** Attacker on VM  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_vis_002`](../rules/zt_vis_002.md)  

> No diagnosticSettings streaming to Log Analytics / Event Hub; on-box actions translated into ARM calls are not correlated anywhere.

**Attacker gain:** Complete blind spot across both host and cloud audit surfaces.


## Blast radius

| | |
|---|---|
| Initial access | Internet-exposed management port on an unmonitored VM. |
| Lateral movement | Whatever the compromised VM can reach - and nobody will see it happening. |
| Max privilege | Local admin on the VM; potentially more via managed identity (see CHAIN-001). |
| Data at risk | Everything on the VM and everything reachable from it |
| Services at risk | Compute, Any service the VM can call |
| Estimated scope | Unknown - the absence of telemetry is the finding |

## How the logic works

The chain fires when the **anchor** rule fires AND at least one of the other triggers fires. The anchor represents the initial foothold; the second rule amplifies it into a meaningful attack. Remediate the anchor to eliminate the entire chain.

