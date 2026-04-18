# CHAIN-031 — Network perimeter collapse

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

No Azure Firewall or equivalent network virtual appliance provides centralized traffic inspection, multiple subnets have no Network Security Groups attached, and the NSGs that do exist allow all outbound traffic. This triple failure collapses the network perimeter into a flat, unmonitored topology. Any attacker who gains access to a single resource on the virtual network - through a compromised VM, a vulnerable application, or a stolen credential - can move laterally to every subnet without crossing a security boundary. Exfiltration is trivial because outbound traffic flows unrestricted to the internet. There is no centralized logging of network flows, no east-west filtering, and no egress control. The environment provides the same network security as a home WiFi router.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_011`](../rules/zt_net_011.md) | Trigger |
| [`zt_net_019`](../rules/zt_net_019.md) | Trigger |
| [`zt_net_018`](../rules/zt_net_018.md) | Trigger |

## Attack walkthrough

### Step 1 — Discover that no network segmentation exists between subnets.

**Actor:** Attacker with initial foothold  
**MITRE ATT&CK:** `T1046`  
**Enabled by:** [`zt_net_019`](../rules/zt_net_019.md)  

> No NSG is attached to the subnet (networkSecurityGroup=null on the subnet resource); all inbound and outbound traffic is allowed by default. ARP/ping sweep reveals all hosts on adjacent subnets.

**Attacker gain:** Full network visibility across all subnets in the virtual network.


### Step 2 — Move laterally to resources on other subnets without any firewall or NSG blocking the connection.

**Actor:** Attacker with network map  
**MITRE ATT&CK:** `T1021`  
**Enabled by:** [`zt_net_019`](../rules/zt_net_019.md)  

> Direct TCP/UDP connections to databases, management ports (RDP/SSH), internal APIs, and storage endpoints on other subnets; no micro-segmentation exists.

**Attacker gain:** Access to resources across multiple subnets - databases, VMs, internal services.


### Step 3 — Confirm that no centralized firewall inspects or logs the lateral movement.

**Actor:** Attacker moving laterally  
**MITRE ATT&CK:** `T1562.004`  
**Enabled by:** [`zt_net_011`](../rules/zt_net_011.md)  

> No Azure Firewall, third-party NVA, or route table forcing traffic through a central inspection point; traffic between subnets goes directly through the Azure fabric with no logging.

**Attacker gain:** Complete freedom of movement with no network-layer detection.


### Step 4 — Exfiltrate data directly to the internet through unrestricted outbound NSG rules.

**Actor:** Attacker with lateral access  
**MITRE ATT&CK:** `T1048`  
**Enabled by:** [`zt_net_018`](../rules/zt_net_018.md)  

> NSGs that exist have outbound rules allowing Destination=* Port=* Protocol=*; there is no Azure Firewall to enforce application-level egress rules or FQDN filtering.

**Attacker gain:** Unrestricted exfiltration path to any internet destination on any port.


### Step 5 — Set up a reverse shell or C2 channel on a high port that blends with legitimate traffic.

**Actor:** Attacker establishing persistence  
**MITRE ATT&CK:** `T1571`  
**Enabled by:** [`zt_net_018`](../rules/zt_net_018.md)  

> Outbound to any port is allowed; attacker establishes HTTPS-based C2 on port 443 to an attacker-controlled domain. No Azure Firewall TLS inspection or FQDN filtering exists to detect the anomalous destination.

**Attacker gain:** Persistent command-and-control channel that is indistinguishable from legitimate HTTPS traffic at the network layer.


### Step 6 — Find no centralized network flow logs or firewall logs to reconstruct the attack path.

**Actor:** Defenders investigating  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_net_011`](../rules/zt_net_011.md)  

> No Azure Firewall means no firewall diagnostic logs; NSG flow logs may not be enabled on the NSGs that exist, and subnets without NSGs have no flow logging at all. Network forensics is impossible.

**Attacker gain:** The attack is invisible at the network layer - no flow records, no firewall logs, no IDS alerts.


## Blast radius

| | |
|---|---|
| Initial access | Any compromised resource on the virtual network. |
| Lateral movement | Unrestricted movement across all subnets - the network is flat. |
| Max privilege | Network-level access to every resource on every subnet. |
| Data at risk | All data on all VNet-connected resources, Database contents, File shares, Internal API data, Management plane credentials exposed on the network |
| Services at risk | All VMs, All databases with VNet endpoints, All internal APIs, All PaaS services with VNet integration, Any service reachable from the virtual network |
| Estimated scope | All resources on the virtual network and connected peered networks |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

