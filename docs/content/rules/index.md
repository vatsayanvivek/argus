# Rule catalog

ARGUS ships **245 Rego rules** organised by zero-trust pillar. Each rule carries NIST 800-53, MITRE ATT&CK, and framework-tag metadata used for compliance mapping and reporting.

Use your browser's search (Ctrl/Cmd+F) or the search box above to find a specific rule ID or keyword.

## Data (60 rules)

| ID | Title | Severity | Chain role |
|---|---|---|---|
| [cis_2_1_23](cis_2_1_23.md) | Defender for Key Vault not enabled | :material-alert: High | ENABLER |
| [cis_2_1_26](cis_2_1_26.md) | Defender for Azure Cosmos DB enabled | :material-alert-circle-outline: Medium | ENABLER |
| [cis_2_1_27](cis_2_1_27.md) | Defender for open-source relational databases enabled | :material-alert-circle-outline: Medium | ENABLER |
| [cis_2_1_28](cis_2_1_28.md) | Defender for Azure SQL Database enabled | :material-alert: High | ENABLER |
| [cis_3_1](cis_3_1.md) | Ensure 'Secure transfer required' is enabled on storage accounts | :material-alert: High | ENABLER |
| [cis_3_16](cis_3_16.md) | Storage account uses private endpoints | :material-alert: High | ENABLER |
| [cis_3_2](cis_3_2.md) | Ensure infrastructure encryption is enabled on storage accounts | :material-alert-circle-outline: Medium | ENABLER |
| [cis_3_3](cis_3_3.md) | Ensure public blob access is disabled on storage accounts | :material-alert-octagon: Critical | ANCHOR |
| [cis_3_4](cis_3_4.md) | Ensure default network access rule is Deny on storage accounts | :material-alert: High | AMPLIFIER |
| [cis_3_5](cis_3_5.md) | Ensure storage accounts use private endpoints | :material-alert-circle-outline: Medium | ENABLER |
| [cis_3_6](cis_3_6.md) | Ensure soft delete is enabled for blob service | :material-alert-circle-outline: Medium | ENABLER |
| [cis_3_7](cis_3_7.md) | Ensure soft delete is enabled for containers | :material-alert-circle-outline: Medium | ENABLER |
| [cis_4_1](cis_4_1.md) | Ensure 'Auditing' is set to On for SQL servers | :material-alert: High | ENABLER |
| [cis_4_2](cis_4_2.md) | Ensure Transparent Data Encryption is enabled on SQL databases | :material-alert: High | ENABLER |
| [cis_4_3](cis_4_3.md) | Ensure SQL server Advanced Data Security is enabled | :material-alert-circle-outline: Medium | ENABLER |
| [cis_4_4](cis_4_4.md) | Ensure public network access is disabled for SQL servers | :material-alert-octagon: Critical | ANCHOR |
| [cis_4_5](cis_4_5.md) | Ensure 'Enforce SSL connection' is enabled for PostgreSQL | :material-alert: High | ENABLER |
| [cis_4_7](cis_4_7.md) | SQL Database has long-term backup retention configured | :material-alert-circle-outline: Medium | AMPLIFIER |
| [cis_7_8](cis_7_8.md) | Virtual Machine managed disks use customer-managed keys | :material-alert-circle-outline: Medium | AMPLIFIER |
| [cis_7_9](cis_7_9.md) | Unattached disks are encrypted with customer-managed key | :material-alert-circle-outline: Medium | AMPLIFIER |
| [cis_8_1](cis_8_1.md) | Ensure Key Vault has soft delete and purge protection enabled | :material-alert-octagon: Critical | ANCHOR |
| [cis_8_2](cis_8_2.md) | Ensure Key Vault keys have rotation policies | :material-alert-circle-outline: Medium | ENABLER |
| [cis_8_4](cis_8_4.md) | Ensure Key Vault uses private endpoints | :material-alert: High | AMPLIFIER |
| [cis_8_5](cis_8_5.md) | Key Vault secrets have expiration date set | :material-alert-circle-outline: Medium | AMPLIFIER |
| [cis_8_6](cis_8_6.md) | Key Vault keys have rotation policy configured | :material-alert-circle-outline: Medium | AMPLIFIER |
| [cis_8_7](cis_8_7.md) | Key Vault uses private endpoint | :material-alert: High | ENABLER |
| [zt_ai_003](zt_ai_003.md) | Cognitive Services account lacks customer-managed key encryption | :material-alert-circle-outline: Medium | ENABLER |
| [zt_ai_005](zt_ai_005.md) | Azure ML Workspace uses the default Microsoft-managed key | :material-alert: High | ENABLER |
| [zt_bak_001](zt_bak_001.md) | Recovery Services Vault lacks immutability protection | :material-alert: High | ENABLER |
| [zt_bak_002](zt_bak_002.md) | Recovery Services Vault has soft delete disabled | :material-alert: High | ENABLER |
| [zt_bak_003](zt_bak_003.md) | Recovery Services Vault has no cross-region restore | :material-alert-circle-outline: Medium | ENABLER |
| [zt_bak_004](zt_bak_004.md) | Recovery Services backup policy has retention below 7 days | :material-alert-circle-outline: Medium | ENABLER |
| [zt_data_001](zt_data_001.md) | Storage account allows public blob access | :material-alert-octagon: Critical | ANCHOR |
| [zt_data_002](zt_data_002.md) | SQL Server Transparent Data Encryption (TDE) disabled | :material-alert: High | ENABLER |
| [zt_data_003](zt_data_003.md) | SQL Server auditing not enabled | :material-alert: High | ENABLER |
| [zt_data_004](zt_data_004.md) | Key Vault soft delete disabled | :material-alert-octagon: Critical | ENABLER |
| [zt_data_005](zt_data_005.md) | Key Vault purge protection disabled | :material-alert-octagon: Critical | ENABLER |
| [zt_data_006](zt_data_006.md) | Storage account encryption-at-rest key source not configured | :material-alert: High | ENABLER |
| [zt_data_007](zt_data_007.md) | SQL Server firewall allows all Azure services | :material-alert: High | AMPLIFIER |
| [zt_data_008](zt_data_008.md) | VM has no backup protection | :material-alert-circle-outline: Medium | ENABLER |
| [zt_data_009](zt_data_009.md) | Key Vault lacks diagnostic settings for secret lifecycle visibility | :material-alert-circle-outline: Medium | ENABLER |
| [zt_data_010](zt_data_010.md) | Storage account not using customer-managed keys (BYOK) | :material-alert-circle-outline: Medium | ENABLER |
| [zt_data_011](zt_data_011.md) | Cosmos DB account allows access from all networks | :material-alert: High | ANCHOR |
| [zt_data_012](zt_data_012.md) | SQL Server auditing not enabled | :material-alert: High | ENABLER |
| [zt_data_013](zt_data_013.md) | Storage account soft delete not enabled for blobs | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_data_014](zt_data_014.md) | Key Vault does not have purge protection enabled | :material-alert: High | ENABLER |
| [zt_data_015](zt_data_015.md) | SQL Database TDE uses service-managed key instead of customer-managed | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_data_016](zt_data_016.md) | Storage account blob versioning not enabled | :material-information-outline: Low | AMPLIFIER |
| [zt_data_017](zt_data_017.md) | Critical resources have no Azure Backup configured | :material-alert: High | ENABLER |
| [zt_data_018](zt_data_018.md) | Event Hub namespace does not use customer-managed key encryption | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_data_019](zt_data_019.md) | Service Bus namespace allows public network access | :material-alert: High | ANCHOR |
| [zt_data_020](zt_data_020.md) | Cognitive Services account allows public network access | :material-alert: High | ANCHOR |
| [zt_data_021](zt_data_021.md) | Azure Data Factory is internet-accessible for integration runtime control plane | :material-alert: High | ANCHOR |
| [zt_data_023](zt_data_023.md) | Synapse workspace allows public SQL endpoint access | :material-alert: High | ANCHOR |
| [zt_data_024](zt_data_024.md) | Redis Cache uses TLS < 1.2 or allows non-SSL port | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_data_025](zt_data_025.md) | Stream Analytics job lacks customer-managed key encryption | :material-alert: High | ENABLER |
| [zt_data_027](zt_data_027.md) | Microsoft Purview account allows public network access | :material-alert-circle-outline: Medium | ANCHOR |
| [zt_data_028](zt_data_028.md) | Synapse Dedicated SQL Pool has no Transparent Data Encryption | :material-alert: High | ENABLER |
| [zt_data_030](zt_data_030.md) | NetApp volume permits NFS v3 (no Kerberos) from mount endpoints | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_data_031](zt_data_031.md) | Storage Data Lake Gen2 container has no ACL-based access control | :material-alert-circle-outline: Medium | ENABLER |

## Identity (49 rules)

| ID | Title | Severity | Chain role |
|---|---|---|---|
| [cis_1_1](cis_1_1.md) | Ensure Multi-Factor Authentication is enabled for all non-privileged users | :material-alert: High | ANCHOR |
| [cis_1_10](cis_1_10.md) | Ensure no more than 3 subscription Owners exist | :material-alert-circle-outline: Medium | ENABLER |
| [cis_1_11](cis_1_11.md) | Ensure disabled user accounts do not hold role assignments | :material-alert: High | AMPLIFIER |
| [cis_1_12](cis_1_12.md) | Ensure guest users do not have privileged role assignments | :material-alert-octagon: Critical | ANCHOR |
| [cis_1_13](cis_1_13.md) | Ensure access reviews exist for privileged roles | :material-alert-circle-outline: Medium | ENABLER |
| [cis_1_14](cis_1_14.md) | Ensure Privileged Identity Management (PIM) is in use | :material-alert-circle-outline: Medium | ENABLER |
| [cis_1_15](cis_1_15.md) | Ensure app registrations do not have high-privilege Graph permissions | :material-alert-octagon: Critical | ANCHOR |
| [cis_1_2](cis_1_2.md) | Ensure MFA is enabled for all privileged users | :material-alert-octagon: Critical | ANCHOR |
| [cis_1_24](cis_1_24.md) | Custom subscription owner roles are not created | :material-alert-circle-outline: Medium | AMPLIFIER |
| [cis_1_25](cis_1_25.md) | Role assignments use groups instead of individual users | :material-information-outline: Low | AMPLIFIER |
| [cis_1_3](cis_1_3.md) | Ensure guest users are reviewed on a regular basis | :material-alert-circle-outline: Medium | ENABLER |
| [cis_1_4](cis_1_4.md) | Ensure no custom subscription owner roles are created | :material-alert: High | AMPLIFIER |
| [cis_1_5](cis_1_5.md) | Ensure all subscription Owners have MFA enabled | :material-alert-octagon: Critical | ANCHOR |
| [cis_1_6](cis_1_6.md) | Ensure that 'Guest invite restrictions' is set to admins only | :material-alert-circle-outline: Medium | ENABLER |
| [cis_1_7](cis_1_7.md) | Ensure no service principal credentials are expired | :material-alert: High | ENABLER |
| [cis_1_8](cis_1_8.md) | Ensure legacy authentication protocols are blocked | :material-alert: High | ENABLER |
| [cis_1_9](cis_1_9.md) | Ensure admins are notified on password resets | :material-information-outline: Low | ENABLER |
| [cis_4_6](cis_4_6.md) | SQL Server uses Azure AD-only authentication | :material-alert: High | ENABLER |
| [cis_9_13](cis_9_13.md) | App Service uses managed identity for authentication | :material-alert-circle-outline: Medium | ENABLER |
| [zt_ai_002](zt_ai_002.md) | Cognitive Services account relies on shared subscription keys (local auth enabled) | :material-alert: High | AMPLIFIER |
| [zt_id_001](zt_id_001.md) | Service Principal credential never expires | :material-alert: High | ENABLER |
| [zt_id_002](zt_id_002.md) | Service not using managed identity | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_id_003](zt_id_003.md) | Permanent privileged role assignment without PIM | :material-alert: High | ENABLER |
| [zt_id_004](zt_id_004.md) | Cross-tenant access unrestricted | :material-alert: High | ENABLER |
| [zt_id_005](zt_id_005.md) | Legacy authentication protocols enabled | :material-alert: High | ENABLER |
| [zt_id_006](zt_id_006.md) | No enabled conditional access policies | :material-alert-octagon: Critical | ENABLER |
| [zt_id_007](zt_id_007.md) | No PIM assignments configured | :material-alert-circle-outline: Medium | ENABLER |
| [zt_id_008](zt_id_008.md) | Service Principal holds Owner/Contributor at subscription scope | :material-alert-octagon: Critical | AMPLIFIER |
| [zt_id_009](zt_id_009.md) | External collaboration unrestricted | :material-alert-circle-outline: Medium | ENABLER |
| [zt_id_010](zt_id_010.md) | No access reviews configured | :material-alert-circle-outline: Medium | ENABLER |
| [zt_id_011](zt_id_011.md) | App Registration holds high-privilege Microsoft Graph permissions | :material-alert-octagon: Critical | ANCHOR |
| [zt_id_012](zt_id_012.md) | No emergency access (break-glass) accounts configured | :material-alert-octagon: Critical | ANCHOR |
| [zt_id_013](zt_id_013.md) | Conditional Access policies do not define named locations | :material-alert: High | ENABLER |
| [zt_id_014](zt_id_014.md) | No authentication strength policy enforced for administrators | :material-alert: High | ENABLER |
| [zt_id_015](zt_id_015.md) | Self-service password reset allows weak authentication methods | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_id_016](zt_id_016.md) | Guest users have excessive directory permissions | :material-alert: High | ENABLER |
| [zt_id_017](zt_id_017.md) | Cross-tenant access settings allow inbound trust by default | :material-alert: High | ENABLER |
| [zt_id_018](zt_id_018.md) | Identity Protection sign-in risk policy not enabled | :material-alert: High | ENABLER |
| [zt_id_019](zt_id_019.md) | Token lifetime exceeds secure threshold | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_id_020](zt_id_020.md) | Administrative units not used for role scoping | :material-information-outline: Low | AMPLIFIER |
| [zt_id_021](zt_id_021.md) | PIM role activation lacks approval workflow | :material-alert: High | ENABLER |
| [zt_id_022](zt_id_022.md) | User risk policy not enabled in Identity Protection | :material-alert: High | ENABLER |
| [zt_id_023](zt_id_023.md) | MFA registration policy not enforced for all users | :material-alert: High | ENABLER |
| [zt_id_024](zt_id_024.md) | Service principal credentials not rotated within 90 days | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_id_025](zt_id_025.md) | Managed identity not used where available | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_id_026](zt_id_026.md) | No access reviews configured for privileged roles | :material-alert: High | ENABLER |
| [zt_int_002](zt_int_002.md) | API Management lacks a system-assigned managed identity | :material-alert-circle-outline: Medium | ENABLER |
| [zt_int_003](zt_int_003.md) | Event Grid / Service Bus / Event Hub namespace allows local auth (SAS keys) | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_wl_026](zt_wl_026.md) | App Configuration store allows local authentication (access keys) | :material-alert-circle-outline: Medium | AMPLIFIER |

## Network (45 rules)

| ID | Title | Severity | Chain role |
|---|---|---|---|
| [cis_2_1_24](cis_2_1_24.md) | Defender for DNS not enabled | :material-alert-circle-outline: Medium | ENABLER |
| [cis_3_17](cis_3_17.md) | Storage account minimum TLS version is 1.2 | :material-alert: High | ENABLER |
| [cis_6_1](cis_6_1.md) | Ensure SSH (port 22) is not exposed to the internet | :material-alert-octagon: Critical | ANCHOR |
| [cis_6_10](cis_6_10.md) | Web Application Firewall (WAF) is enabled for Application Gateway | :material-alert: High | ENABLER |
| [cis_6_11](cis_6_11.md) | Ensure management VMs do not have public IP addresses | :material-alert: High | AMPLIFIER |
| [cis_6_2](cis_6_2.md) | Ensure RDP (port 3389) is not exposed to the internet | :material-alert-octagon: Critical | ANCHOR |
| [cis_6_3](cis_6_3.md) | Ensure UDP services are not exposed to the internet | :material-alert: High | AMPLIFIER |
| [cis_6_7](cis_6_7.md) | Azure Firewall Premium SKU not deployed | :material-alert: High | ENABLER |
| [cis_6_9](cis_6_9.md) | Public IP addresses not associated with DDoS protection | :material-alert-circle-outline: Medium | AMPLIFIER |
| [cis_9_11](cis_9_11.md) | App Service uses latest TLS version | :material-alert: High | ENABLER |
| [cis_9_14](cis_9_14.md) | App Service restricts CORS to specific origins | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_ai_006](zt_ai_006.md) | Azure ML compute cluster does not enforce SSH to private network | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_data_022](zt_data_022.md) | Databricks workspace deploys worker VMs with public IPs | :material-alert: High | AMPLIFIER |
| [zt_data_026](zt_data_026.md) | HDInsight cluster deploys with public gateway enabled | :material-alert: High | ANCHOR |
| [zt_data_029](zt_data_029.md) | MariaDB server requires SSL or uses minimum TLS version 1.2 | :material-alert: High | AMPLIFIER |
| [zt_int_001](zt_int_001.md) | API Management instance accepts weak TLS on the gateway | :material-alert: High | AMPLIFIER |
| [zt_int_004](zt_int_004.md) | Logic App workflow accepts HTTP trigger from anywhere with no IP restriction | :material-alert: High | ANCHOR |
| [zt_int_005](zt_int_005.md) | Traffic Manager profile uses HTTP (not HTTPS) for probes | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_int_006](zt_int_006.md) | Front Door profile accepts TLS below 1.2 | :material-alert: High | AMPLIFIER |
| [zt_int_008](zt_int_008.md) | API Management is not deployed in internal-VNet mode for sensitive backends | :material-alert-circle-outline: Medium | ENABLER |
| [zt_net_001](zt_net_001.md) | NSG allows SSH (22) from the Internet | :material-alert-octagon: Critical | ANCHOR |
| [zt_net_002](zt_net_002.md) | NSG allows RDP (3389) from the Internet | :material-alert-octagon: Critical | ANCHOR |
| [zt_net_003](zt_net_003.md) | Subnet has no associated Network Security Group | :material-alert: High | ENABLER |
| [zt_net_004](zt_net_004.md) | VNet peering without central firewall inspection | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_net_005](zt_net_005.md) | No Azure Firewall or NVA deployed | :material-alert-circle-outline: Medium | ENABLER |
| [zt_net_006](zt_net_006.md) | Virtual Machine has a direct public IP | :material-alert: High | ANCHOR |
| [zt_net_007](zt_net_007.md) | VNet missing DDoS protection | :material-alert-circle-outline: Medium | ENABLER |
| [zt_net_008](zt_net_008.md) | Application Gateway without WAF | :material-alert: High | ENABLER |
| [zt_net_009](zt_net_009.md) | Storage account network default action is Allow | :material-alert: High | AMPLIFIER |
| [zt_net_010](zt_net_010.md) | PaaS resource missing private endpoint | :material-alert-circle-outline: Medium | ENABLER |
| [zt_net_011](zt_net_011.md) | Azure Firewall not deployed in hub virtual network | :material-alert: High | ENABLER |
| [zt_net_012](zt_net_012.md) | Azure Firewall threat intelligence mode not set to Alert and Deny | :material-alert: High | AMPLIFIER |
| [zt_net_013](zt_net_013.md) | Virtual network has no DDoS protection plan | :material-alert-circle-outline: Medium | ENABLER |
| [zt_net_014](zt_net_014.md) | Application Gateway does not have WAF enabled | :material-alert: High | ENABLER |
| [zt_net_015](zt_net_015.md) | VPN Gateway not using IKEv2 or OpenVPN protocol | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_net_016](zt_net_016.md) | Network Watcher not enabled in all regions | :material-alert-circle-outline: Medium | ENABLER |
| [zt_net_017](zt_net_017.md) | Front Door does not have WAF policy attached | :material-alert: High | ENABLER |
| [zt_net_018](zt_net_018.md) | NSG allows all outbound traffic to the Internet | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_net_019](zt_net_019.md) | Subnet has no Network Security Group associated | :material-alert: High | ENABLER |
| [zt_net_020](zt_net_020.md) | Virtual network peering allows forwarded traffic from remote | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_net_021](zt_net_021.md) | VPN Gateway uses a deprecated Basic SKU | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_net_022](zt_net_022.md) | Private DNS Zone has no virtual-network link — private endpoints unreachable | :material-alert-circle-outline: Medium | ENABLER |
| [zt_net_023](zt_net_023.md) | ExpressRoute circuit does not use MACsec encryption | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_net_024](zt_net_024.md) | NAT Gateway has no idle timeout configured for long-lived connections | :material-information-outline: Low | ENABLER |
| [zt_wl_025](zt_wl_025.md) | Container App is externally-ingressed and allows insecure HTTP | :material-alert: High | AMPLIFIER |

## Visibility (47 rules)

| ID | Title | Severity | Chain role |
|---|---|---|---|
| [cis_2_1](cis_2_1.md) | Ensure Microsoft Defender for Servers is set to Standard | :material-alert: High | ENABLER |
| [cis_2_1_25](cis_2_1_25.md) | Defender for Resource Manager not enabled | :material-alert-circle-outline: Medium | ENABLER |
| [cis_2_2](cis_2_2.md) | Ensure Microsoft Defender for App Service is set to Standard | :material-alert: High | ENABLER |
| [cis_2_3](cis_2_3.md) | Ensure Microsoft Defender for SQL Servers is set to Standard | :material-alert: High | ENABLER |
| [cis_2_4](cis_2_4.md) | Ensure Microsoft Defender for Storage is set to Standard | :material-alert: High | ENABLER |
| [cis_2_5](cis_2_5.md) | Ensure Microsoft Defender for Containers is set to Standard | :material-alert: High | ENABLER |
| [cis_2_6](cis_2_6.md) | Ensure Microsoft Defender for Key Vault is set to Standard | :material-alert: High | ENABLER |
| [cis_2_7](cis_2_7.md) | Ensure Microsoft Defender for DNS is set to Standard | :material-alert: High | ENABLER |
| [cis_2_8](cis_2_8.md) | Ensure Microsoft Defender for Resource Manager is set to Standard | :material-alert: High | ENABLER |
| [cis_3_8](cis_3_8.md) | Ensure storage account diagnostic logs are enabled | :material-alert-circle-outline: Medium | ENABLER |
| [cis_5_1](cis_5_1.md) | Ensure a diagnostic setting exists at subscription scope | :material-alert: High | ENABLER |
| [cis_5_2](cis_5_2.md) | Ensure Activity Log retention is 365 days or more | :material-alert-circle-outline: Medium | ENABLER |
| [cis_5_3](cis_5_3.md) | Ensure activity log alert exists for Create Policy Assignment | :material-alert-circle-outline: Medium | ENABLER |
| [cis_5_4](cis_5_4.md) | Ensure activity log alert exists for NSG rule changes | :material-alert-circle-outline: Medium | ENABLER |
| [cis_5_5](cis_5_5.md) | Ensure activity log alert exists for SQL firewall rule changes | :material-alert-circle-outline: Medium | ENABLER |
| [cis_5_6](cis_5_6.md) | Ensure activity log alert exists for Security Solution changes | :material-alert-circle-outline: Medium | ENABLER |
| [cis_5_7](cis_5_7.md) | Azure Monitor Diagnostic Settings captures all categories | :material-alert-circle-outline: Medium | AMPLIFIER |
| [cis_5_8](cis_5_8.md) | Activity Log retention set to 365 days or more | :material-alert-circle-outline: Medium | AMPLIFIER |
| [cis_5_9](cis_5_9.md) | Network Security Group flow log retention set to >= 90 days | :material-alert-circle-outline: Medium | AMPLIFIER |
| [cis_6_4](cis_6_4.md) | Ensure Network Watcher is enabled | :material-alert-circle-outline: Medium | ENABLER |
| [cis_6_5](cis_6_5.md) | Ensure NSG flow logs are enabled | :material-alert-circle-outline: Medium | ENABLER |
| [cis_6_8](cis_6_8.md) | NSG flow logs not enabled for all NSGs | :material-alert-circle-outline: Medium | AMPLIFIER |
| [cis_7_4](cis_7_4.md) | Ensure vulnerability assessment is enabled on VMs | :material-alert-circle-outline: Medium | ENABLER |
| [cis_8_3](cis_8_3.md) | Ensure Key Vault has diagnostic settings enabled | :material-alert-circle-outline: Medium | ENABLER |
| [zt_int_007](zt_int_007.md) | API Management instance has no diagnostic logs routed to Log Analytics or Event Hub | :material-alert-circle-outline: Medium | ENABLER |
| [zt_vis_001](zt_vis_001.md) | Security-relevant resource has no diagnostic settings | :material-alert: High | ENABLER |
| [zt_vis_002](zt_vis_002.md) | No Log Analytics workspace in subscription | :material-alert: High | ENABLER |
| [zt_vis_003](zt_vis_003.md) | Microsoft Defender for Cloud plans on Free tier | :material-alert-circle-outline: Medium | ENABLER |
| [zt_vis_004](zt_vis_004.md) | No alerting on critical management operations | :material-alert: High | ENABLER |
| [zt_vis_005](zt_vis_005.md) | Activity log retention appears insufficient | :material-alert-circle-outline: Medium | ENABLER |
| [zt_vis_006](zt_vis_006.md) | NSG flow logs disabled | :material-alert: High | ENABLER |
| [zt_vis_007](zt_vis_007.md) | No Microsoft Sentinel deployment found | :material-alert: High | ENABLER |
| [zt_vis_008](zt_vis_008.md) | No alert on Owner role assignment | :material-alert: High | ENABLER |
| [zt_vis_009](zt_vis_009.md) | No Network Watcher in subscription | :material-alert-circle-outline: Medium | ENABLER |
| [zt_vis_010](zt_vis_010.md) | Just-in-Time VM access not configured | :material-alert-circle-outline: Medium | ENABLER |
| [zt_vis_011](zt_vis_011.md) | No Log Analytics workspace configured in subscription | :material-alert: High | ENABLER |
| [zt_vis_012](zt_vis_012.md) | No Azure Monitor alert rules configured for critical operations | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_vis_013](zt_vis_013.md) | NSG flow log retention period is less than 90 days | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_vis_014](zt_vis_014.md) | Key Vault diagnostic logging not enabled | :material-alert: High | ENABLER |
| [zt_vis_015](zt_vis_015.md) | SQL Server audit log retention less than 90 days | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_vis_016](zt_vis_016.md) | Storage account access logging not enabled | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_vis_017](zt_vis_017.md) | Activity log not exported to Log Analytics workspace | :material-alert: High | ENABLER |
| [zt_vis_018](zt_vis_018.md) | No Azure Monitor action groups configured | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_vis_019](zt_vis_019.md) | Application Insights not configured for web applications | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_vis_020](zt_vis_020.md) | Defender for Cloud email notifications not configured | :material-information-outline: Low | AMPLIFIER |
| [zt_vis_021](zt_vis_021.md) | No Activity Log alert for role assignment creation at subscription scope | :material-alert-circle-outline: Medium | ENABLER |
| [zt_vis_022](zt_vis_022.md) | No Activity Log alert for Key Vault 'listKeys' or 'listSecrets' operations | :material-alert-circle-outline: Medium | ENABLER |

## Workload (44 rules)

| ID | Title | Severity | Chain role |
|---|---|---|---|
| [cis_2_1_22](cis_2_1_22.md) | Defender for Containers not enabled | :material-alert: High | ENABLER |
| [cis_7_1](cis_7_1.md) | Ensure endpoint protection is installed on VMs | :material-alert: High | ENABLER |
| [cis_7_10](cis_7_10.md) | Only approved VM extensions are installed | :material-alert-circle-outline: Medium | AMPLIFIER |
| [cis_7_2](cis_7_2.md) | Ensure encryption at host is enabled on VMs | :material-alert: High | ENABLER |
| [cis_7_3](cis_7_3.md) | Ensure VM data disks are encrypted | :material-alert: High | ENABLER |
| [cis_9_1](cis_9_1.md) | Ensure App Service requires HTTPS only | :material-alert: High | ENABLER |
| [cis_9_12](cis_9_12.md) | App Service disables FTP deployment | :material-alert: High | ENABLER |
| [cis_9_2](cis_9_2.md) | Ensure App Service minimum TLS version is 1.2 | :material-alert: High | ENABLER |
| [cis_9_3](cis_9_3.md) | Ensure App Service remote debugging is disabled | :material-alert: High | ENABLER |
| [cis_9_4](cis_9_4.md) | Ensure App Service has HTTP/2 enabled | :material-information-outline: Low | ENABLER |
| [cis_9_5](cis_9_5.md) | Ensure App Service uses managed identity | :material-alert-circle-outline: Medium | ENABLER |
| [zt_ai_001](zt_ai_001.md) | Azure OpenAI / Cognitive Services account is exposed to the public internet | :material-alert: High | ANCHOR |
| [zt_ai_004](zt_ai_004.md) | Azure ML Workspace is internet-exposed | :material-alert: High | ANCHOR |
| [zt_ai_007](zt_ai_007.md) | Bot Service endpoint lacks managed identity authentication | :material-alert-circle-outline: Medium | ENABLER |
| [zt_bak_005](zt_bak_005.md) | Site Recovery replication policy uses inadequate RPO | :material-alert: High | ENABLER |
| [zt_wl_001](zt_wl_001.md) | Virtual Machine has no managed identity | :material-alert: High | AMPLIFIER |
| [zt_wl_002](zt_wl_002.md) | Container image pulled from public registry | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_wl_003](zt_wl_003.md) | AKS API server is publicly reachable without IP allowlist | :material-alert-octagon: Critical | ANCHOR |
| [zt_wl_004](zt_wl_004.md) | Function App has no authentication enabled | :material-alert-octagon: Critical | ANCHOR |
| [zt_wl_005](zt_wl_005.md) | App Service allows HTTP (not HTTPS only) | :material-alert: High | AMPLIFIER |
| [zt_wl_006](zt_wl_006.md) | VM missing vulnerability assessment extension | :material-alert-circle-outline: Medium | ENABLER |
| [zt_wl_007](zt_wl_007.md) | AKS cluster allows privileged containers | :material-alert: High | AMPLIFIER |
| [zt_wl_008](zt_wl_008.md) | App Service has remote debugging enabled | :material-alert: High | ENABLER |
| [zt_wl_009](zt_wl_009.md) | VM missing antimalware extension | :material-alert-circle-outline: Medium | ENABLER |
| [zt_wl_010](zt_wl_010.md) | Shared user-assigned managed identity across workloads | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_wl_011](zt_wl_011.md) | App Service uses legacy Easy Auth v1 without client auth enforcement | :material-alert: High | ANCHOR |
| [zt_wl_012](zt_wl_012.md) | Container Registry has admin account enabled | :material-alert: High | ENABLER |
| [zt_wl_013](zt_wl_013.md) | Container Registry allows public network access | :material-alert: High | ANCHOR |
| [zt_wl_014](zt_wl_014.md) | AKS cluster has no network policy configured | :material-alert: High | ENABLER |
| [zt_wl_015](zt_wl_015.md) | AKS cluster does not use Azure RBAC for Kubernetes authorization | :material-alert: High | ENABLER |
| [zt_wl_016](zt_wl_016.md) | AKS cluster does not enforce pod security standards | :material-alert: High | AMPLIFIER |
| [zt_wl_017](zt_wl_017.md) | Function App uses outdated runtime version | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_wl_018](zt_wl_018.md) | App Service has remote debugging enabled | :material-alert: High | ANCHOR |
| [zt_wl_019](zt_wl_019.md) | App Service does not require client certificates | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_wl_020](zt_wl_020.md) | Virtual Machine disk encryption not enabled | :material-alert: High | ENABLER |
| [zt_wl_021](zt_wl_021.md) | Defender for Containers not enabled on AKS cluster | :material-alert: High | ENABLER |
| [zt_wl_022](zt_wl_022.md) | AKS cluster does not use Key Vault CSI driver for secrets | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_wl_023](zt_wl_023.md) | AKS cluster does not use private API server | :material-alert: High | ANCHOR |
| [zt_wl_024](zt_wl_024.md) | AKS cluster does not have Azure Policy add-on enabled | :material-alert-circle-outline: Medium | AMPLIFIER |
| [zt_wl_027](zt_wl_027.md) | Virtual Machine Scale Set does not use managed identity | :material-alert: High | ENABLER |
| [zt_wl_028](zt_wl_028.md) | Service Fabric cluster uses certificate thumbprint auth instead of Entra ID | :material-alert: High | ENABLER |
| [zt_wl_029](zt_wl_029.md) | VMSS has no automatic OS-image upgrade policy | :material-alert-circle-outline: Medium | ENABLER |
| [zt_wl_030](zt_wl_030.md) | Container App Environment is zone-redundant but has no managed identity | :material-alert: High | ENABLER |
| [zt_wl_031](zt_wl_031.md) | Batch account accepts public-endpoint pool access (no private endpoint) | :material-alert: High | ANCHOR |

