# CHAIN-040 — Identity Protection Gap to Account Takeover

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Entra ID Identity Protection is effectively disabled: no sign-in risk policy detects anomalous authentication patterns (impossible travel, password spray indicators, anonymous IP usage), and no user risk policy flags accounts whose credentials have appeared in dark web breaches. Self-Service Password Reset is configured with weak authentication methods - a single SMS or security question - rather than requiring strong factors. This creates a complete identity protection vacuum. An attacker password-sprays the tenant, compromises an account, and Entra never raises a sign-in risk event because the policy is not enabled. The compromised account is never flagged as 'at risk' because no user risk policy processes the signals. The attacker then uses SSPR with a weak method to reset the password, locking out the legitimate user and establishing full control of the account. From there, the attacker resets other accounts using the same SSPR weakness, creating a cascading compromise that Identity Protection would have stopped at step one.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_018`](../rules/zt_id_018.md) | Trigger |
| [`zt_id_022`](../rules/zt_id_022.md) | Trigger |
| [`zt_id_015`](../rules/zt_id_015.md) | Trigger |

## Attack walkthrough

### Step 1 — Execute a low-and-slow password spray against the tenant's authentication endpoints.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1110.003`  
**Enabled by:** [`zt_id_018`](../rules/zt_id_018.md)  

> Spray one common password against thousands of accounts per hour via https://login.microsoftonline.com/common/oauth2/token; stay below smart lockout thresholds.

**Attacker gain:** One or more valid username/password pairs. Sign-in risk policy would have flagged the spray pattern - but it is not enabled.


### Step 2 — Authenticate as the compromised user; Entra ID does not challenge or block the anomalous sign-in.

**Actor:** Attacker with valid credentials  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_018`](../rules/zt_id_018.md)  

> Sign-in from an anonymous VPN IP with impossible travel from the user's last known location; Identity Protection generates the risk signal internally but no policy acts on it.

**Attacker gain:** Full session access as the compromised user with no risk-based Conditional Access challenge.


### Step 3 — Initiate Self-Service Password Reset using a weak method to change the password and lock out the legitimate user.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1098.005`  
**Enabled by:** [`zt_id_015`](../rules/zt_id_015.md)  

> SSPR flow at https://passwordreset.microsoftonline.com/ accepts a single SMS verification or security question; attacker has harvested the phone number via social engineering or SIM swap.

**Attacker gain:** Full account takeover: password changed, legitimate user locked out, attacker is now the sole credential holder.


### Step 4 — Register new MFA methods and disable the old ones to cement persistence.

**Actor:** Attacker with account control  
**MITRE ATT&CK:** `T1556.006`  
**Enabled by:** [`zt_id_022`](../rules/zt_id_022.md)  

> Navigate to https://mysignins.microsoft.com/security-info; register attacker-controlled authenticator app; remove victim's phone number. No user risk policy flags this as suspicious.

**Attacker gain:** Durable MFA persistence - even if the password is reset by IT, the attacker's MFA method remains registered.


### Step 5 — Use the compromised account's access to target additional high-value accounts via the same SSPR weakness.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1136.003`  
**Enabled by:** [`zt_id_015`](../rules/zt_id_015.md)  

> If the compromised account has Helpdesk or User Administrator role, directly reset passwords for other users. Otherwise, use directory enumeration to identify targets and repeat the SSPR attack.

**Attacker gain:** Cascading account compromise across the tenant, potentially reaching Global Administrator accounts.


### Step 6 — Exfiltrate data, establish persistence, and prepare for destructive action across the compromised accounts.

**Actor:** Attacker with multiple accounts  
**MITRE ATT&CK:** `T1530`  
**Enabled by:** [`zt_id_022`](../rules/zt_id_022.md)  

> Access SharePoint, Exchange, Teams data across all compromised identities; create backdoor app registrations; grant consent to malicious applications.

**Attacker gain:** Broad tenant compromise with persistent access across multiple identities and no Identity Protection remediation trigger.


## Blast radius

| | |
|---|---|
| Initial access | Password spray against tenant authentication endpoints, undetected by absent sign-in risk policy. |
| Lateral movement | Compromised account → SSPR takeover of additional accounts → cascading identity compromise. |
| Max privilege | Whatever roles the compromised accounts hold, potentially escalating to Global Administrator via cascading SSPR attacks. |
| Data at risk | All data accessible to compromised identities, Exchange mailboxes, SharePoint/OneDrive files, Teams messages, Azure resource data |
| Services at risk | Entra ID, Exchange Online, SharePoint Online, OneDrive, Microsoft Teams, Azure subscriptions |
| Estimated scope | Potentially 100% of the tenant if cascading compromise reaches Global Administrator |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

