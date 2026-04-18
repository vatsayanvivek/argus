# CHAIN-114 — DDoS protection disabled on internet-facing resources

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

VNets hosting internet-facing apps do not have DDoS Protection Standard. A volumetric attack takes the app offline; the business lives with rate-limit downtime plus reputational damage.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_012`](../rules/zt_net_012.md) | Trigger |
| [`zt_net_007`](../rules/zt_net_007.md) | Trigger |

## Attack walkthrough

### Step 1 — Launch volumetric UDP flood on public IP.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1498.001`  
**Enabled by:** [`zt_net_012`](../rules/zt_net_012.md)  

**Attacker gain:** Downtime within seconds.


### Step 2 — Sustain attack; basic DDoS mitigation (per-IP throttle) cannot absorb.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1498`  
**Enabled by:** [`zt_net_007`](../rules/zt_net_007.md)  

**Attacker gain:** Extended outage.


## Blast radius

| | |
|---|---|
| Initial access | Internet DDoS sources. |
| Max privilege | Availability denial. |
| Data at risk | Service availability |
| Services at risk | Any public-facing Azure resource |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

