# CHAIN-050 — Defender notification black hole - detections without response

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Microsoft Defender for Cloud is generating security alerts, but nobody is listening. Email notifications for Defender alerts are not configured, so high-severity detections like 'Suspicious login to VM', 'Crypto mining activity detected', or 'Mass secret access from Key Vault' sit unread in the Azure portal. No Azure Monitor alert rules are configured to catch activity log events (resource deletions, role assignments, policy changes), so control-plane abuse generates no notification. And no Action Groups are defined, meaning even if someone were to create an alert rule, there is no delivery mechanism (email, SMS, webhook, ITSM ticket) to route it to a human. The practical effect: the organisation is paying for Defender's detection engine but has zero response capability. Every detection rots in the portal, and attackers operate with unlimited dwell time because no one is ever told to look.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_vis_020`](../rules/zt_vis_020.md) | Trigger |
| [`zt_vis_012`](../rules/zt_vis_012.md) | Trigger |
| [`zt_vis_018`](../rules/zt_vis_018.md) | Trigger |

## Attack walkthrough

### Step 1 — Trigger a Defender for Cloud alert through malicious activity that Defender is designed to detect.

**Actor:** Any attacker (any TTP)  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_vis_020`](../rules/zt_vis_020.md)  

> Defender detects activity such as T1110 (brute force), T1496 (crypto mining), T1555.006 (Key Vault secret mass-read), or T1078.004 (suspicious cloud identity use). An alert is generated with severity High or Critical and stored in the SecurityAlert table.

**Attacker gain:** The attack is detected by Defender, but the detection has no delivery path to a human responder.


### Step 2 — Defender attempts to send email notification but no recipients are configured.

**Actor:** System (no action)  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_vis_020`](../rules/zt_vis_020.md)  

> Security Center email notification settings (zt_vis_020) have no email addresses configured. The 'Send email notification for high severity alerts' toggle may be on, but with no recipients, the notification is silently discarded.

**Attacker gain:** High and critical severity Defender alerts accumulate in the portal with no email delivery.


### Step 3 — Activity log events (resource modifications, role changes, policy updates) occur without triggering any alert rule.

**Actor:** System (no action)  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_vis_012`](../rules/zt_vis_012.md)  

> No Azure Monitor alert rules are configured (zt_vis_012). Administrative operations like Microsoft.Authorization/roleAssignments/write, Microsoft.Resources/subscriptions/resourceGroups/delete, and Microsoft.KeyVault/vaults/secrets/getSecret generate activity log entries but no alert evaluation occurs.

**Attacker gain:** Control-plane abuse is logged but never evaluated against alert conditions - no notification is possible.


### Step 4 — Even manual alert rule creation would fail to notify because no Action Groups exist as delivery endpoints.

**Actor:** System (no action)  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_vis_018`](../rules/zt_vis_018.md)  

> No Azure Monitor Action Groups are configured (zt_vis_018). Action Groups are the sole mechanism for delivering notifications (email, SMS, webhook, Logic App, ITSM) from Azure Monitor. Without them, the notification pipeline has no terminus.

**Attacker gain:** The entire Azure notification infrastructure is non-functional: detection exists, but the delivery chain is broken at every link.


### Step 5 — Operate with unlimited dwell time, escalate privileges, exfiltrate data, and establish persistence without time pressure.

**Actor:** Attacker (unrestricted dwell)  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_vis_012`](../rules/zt_vis_012.md)  

> With no notification reaching any human, the attacker's dwell time is bounded only by when someone happens to log into the Azure portal and navigate to Defender alerts. Industry data shows unnotified breaches average 200+ days before detection. The attacker has months to achieve objectives.

**Attacker gain:** Months of undetected access to escalate, pivot, exfiltrate, and establish durable persistence.


## Blast radius

| | |
|---|---|
| Initial access | Any attack vector - this chain amplifies all others by eliminating the notification response loop. |
| Lateral movement | Unlimited - the attacker is never interrupted because no one is notified of Defender detections. |
| Max privilege | Whatever the attacker can achieve given unlimited, undetected dwell time. |
| Data at risk | All data in the subscription, The scope depends entirely on the undetected attack's progression |
| Services at risk | Microsoft Defender for Cloud (detections wasted), Azure Monitor (no alert rules), All Azure services (unmonitored) |
| Estimated scope | 100% of all subscriptions in the Defender scope |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

