# CHAIN-033 — PIM Abuse to Silent Privilege Escalation

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Privileged Identity Management is configured but critically weakened: eligible role assignments require no approval workflow, the Activity Log is not exported to a durable sink, and access token lifetimes are set far beyond recommended thresholds. An attacker who compromises any PIM-eligible account can self-activate to Global Administrator or equivalent without a second pair of eyes approving the request. The activation event is written to the Azure Activity Log, but since that log is not exported to Log Analytics or a SIEM, no alert fires and the 90-day native retention silently expires the evidence. The long-lived token means the attacker holds the elevated privilege for hours - far longer than the activation window - giving them time to establish persistence, exfiltrate data, and clean up before anyone notices.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_021`](../rules/zt_id_021.md) | Trigger |
| [`zt_vis_017`](../rules/zt_vis_017.md) | Trigger |
| [`zt_id_019`](../rules/zt_id_019.md) | Trigger |

## Attack walkthrough

### Step 1 — Enumerate PIM-eligible role assignments and identify high-privilege roles that require no approval.

**Actor:** Attacker with compromised eligible account  
**MITRE ATT&CK:** `T1087.004`  
**Enabled by:** [`zt_id_021`](../rules/zt_id_021.md)  

> GET /beta/roleManagement/directory/roleEligibilityScheduleInstances; inspect each role's policy: approvalRequired=false, no approvers configured.

**Attacker gain:** List of self-activatable privileged roles with no human gate.


### Step 2 — Self-activate a Global Administrator or Privileged Role Administrator assignment through PIM.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_021`](../rules/zt_id_021.md)  

> POST /beta/roleManagement/directory/roleAssignmentScheduleRequests with action=selfActivate, justification='Routine maintenance'; no approver is in the loop.

**Attacker gain:** Active Global Administrator role assignment for the configured activation duration.


### Step 3 — Create a backdoor service principal with Owner role and a long-lived client secret for durable access.

**Actor:** Attacker with GA role  
**MITRE ATT&CK:** `T1136.003`  
**Enabled by:** [`zt_vis_017`](../rules/zt_vis_017.md)  

> New-MgApplication + New-MgServicePrincipal + New-MgRoleAssignment; all audit events land in AuditLogs/ActivityLog.

**Attacker gain:** Persistent non-human identity that survives the PIM activation window.


### Step 4 — Rely on the long-lived access token to continue operating after the PIM window would logically close.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1550.001`  
**Enabled by:** [`zt_id_019`](../rules/zt_id_019.md)  

> Token lifetime policy allows tokens valid for 4-8+ hours; even after PIM deactivation, cached tokens remain valid until expiry. ARM and Graph honor the token until exp claim.

**Attacker gain:** Extended operational window well beyond the PIM activation period.


### Step 5 — Exfiltrate sensitive data and erase traces, knowing the Activity Log is not forwarded.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1070.009`  
**Enabled by:** [`zt_vis_017`](../rules/zt_vis_017.md)  

> Activity Log events exist in the portal for 90 days but are not streamed to Log Analytics, Event Hub, or Storage. No SIEM correlation, no automated alert, no SOC ticket.

**Attacker gain:** Complete operational security - the activation, persistence, and exfiltration events age out of native retention with no one having seen them.


## Blast radius

| | |
|---|---|
| Initial access | Any account with PIM-eligible privileged role assignment. |
| Lateral movement | PIM self-activation → Global Administrator → service principal creation → any resource in the tenant. |
| Max privilege | Global Administrator with no approval gate, extended by long-lived tokens. |
| Data at risk | Entire Entra ID tenant, All Azure subscriptions, All Microsoft 365 data, Key Vault secrets tenant-wide |
| Services at risk | Entra ID, PIM, All Azure subscriptions, Microsoft 365, Key Vault |
| Estimated scope | 100% of the tenant |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

