# CHAIN-178 — Update Management exclusions for prod hosts

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Prod hosts are excluded from Update Management schedules to 'avoid outage risk'. They accumulate critical CVEs for months. One in-the-wild exploit yields fleet-wide compromise because the patches were deliberately skipped.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_bak_005`](../rules/zt_bak_005.md) | Trigger |
| [`zt_wl_008`](../rules/zt_wl_008.md) | Trigger |

## Attack walkthrough

### Step 1 — High-impact CVE with public exploit.

**Actor:** CVE publication  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_bak_005`](../rules/zt_bak_005.md)  

**Attacker gain:** Exploit for stale prod hosts.


### Step 2 — Attack unpatched fleet; every excluded host is vulnerable.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1210`  
**Enabled by:** [`zt_wl_008`](../rules/zt_wl_008.md)  

**Attacker gain:** Fleet compromise.


## Blast radius

| | |
|---|---|
| Initial access | Public exploit + excluded hosts. |
| Max privilege | RCE on prod fleet. |
| Data at risk | Prod workload data |
| Services at risk | Every excluded host |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

