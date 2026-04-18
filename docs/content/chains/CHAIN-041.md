# CHAIN-041 — Complete Visibility Blind Spot

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

The environment has achieved total visibility blindness. No Log Analytics workspace exists to aggregate telemetry, the Azure Activity Log is not exported to any durable sink, and no Action Groups are configured to route alerts to human responders. Every other security control in the environment is operating in the dark: Defender for Cloud may generate recommendations, NSGs may log flows, Identity Protection may detect risks - but none of that matters because no one is watching, no telemetry is retained beyond default periods, and no alert ever reaches a phone, inbox, or Slack channel. This is not a single missing log source; it is a systemic architectural failure that renders the entire security posture decorative. Any attacker who gains any foothold operates with effectively infinite dwell time because the feedback loop from detection to response does not exist.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_vis_011`](../rules/zt_vis_011.md) | Trigger |
| [`zt_vis_017`](../rules/zt_vis_017.md) | Trigger |
| [`zt_vis_018`](../rules/zt_vis_018.md) | Trigger |

## Attack walkthrough

### Step 1 — Confirm that no centralized logging infrastructure exists by observing the absence of monitoring responses to deliberately noisy actions.

**Actor:** Any attacker with any initial access vector  
**MITRE ATT&CK:** `T1497.001`  
**Enabled by:** [`zt_vis_011`](../rules/zt_vis_011.md)  

> Create a test resource group, modify an NSG rule, trigger a sign-in from an anomalous location - wait for any response. None comes because no Log Analytics workspace ingests the events.

**Attacker gain:** Certainty that actions are not being monitored or correlated.


### Step 2 — Perform privilege escalation and persistence actions that emit Activity Log events, knowing those events are not exported.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1098`  
**Enabled by:** [`zt_vis_017`](../rules/zt_vis_017.md)  

> Role assignments, policy exemptions, resource locks removed, diagnostic settings deleted - all generate Activity Log entries that exist only in the portal for 90 days with no export.

**Attacker gain:** Privilege escalation with a 90-day evidence expiry timer that is ticking in the attacker's favor.


### Step 3 — Establish multiple persistence mechanisms knowing that even if a control detects one, no alert will reach a human.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1136.003`  
**Enabled by:** [`zt_vis_018`](../rules/zt_vis_018.md)  

> Backdoor service principal, modified Conditional Access policy, new PIM eligible assignment, webhook on a Logic App - each would generate an alert in a configured environment, but no Action Group exists.

**Attacker gain:** Redundant persistence across identity, workload, and automation layers.


### Step 4 — Exfiltrate data at leisure over days or weeks, adjusting pace based on the complete absence of defensive response.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1567.002`  
**Enabled by:** [`zt_vis_011`](../rules/zt_vis_011.md)  

> Staged exfiltration via Storage Account copy, Logic App export, or Graph API bulk download - no anomaly detection, no bandwidth alert, no SOC analyst review.

**Attacker gain:** Complete data exfiltration with zero detection pressure.


### Step 5 — Optionally execute destructive actions knowing that incident response cannot begin until a user manually notices something is wrong.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1485`  
**Enabled by:** [`zt_vis_018`](../rules/zt_vis_018.md)  

> Resource deletion, encryption with attacker-controlled keys, DNS hijacking - the mean time to detect is measured in days or weeks because the only detection mechanism is a human noticing a broken application.

**Attacker gain:** Maximum impact with maximum dwell time; incident response starts from zero context because no historical telemetry exists.


## Blast radius

| | |
|---|---|
| Initial access | Any initial access vector - this chain amplifies every other attack by removing detection. |
| Lateral movement | Unrestricted - no visibility means no detection at any stage of lateral movement. |
| Max privilege | Whatever the attacker accumulates over an unlimited dwell time. |
| Data at risk | All data in the environment, Historical forensic data is unrecoverable, Incident response starts from zero |
| Services at risk | All Azure services, All Entra ID objects, All Microsoft 365 workloads |
| Estimated scope | 100% - visibility failure is environment-wide |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

