package iac

import (
	"strings"

	"github.com/vatsayanvivek/argus/internal/models"
)

// genericTypeSpec declares how to translate a Terraform resource type
// for which a bespoke handler would be over-engineered. The registry
// below lets us reach Checkov-class coverage (~150 types) without 120
// near-duplicate translator functions. The flow:
//
//   1. dispatch in Translate() checks the hand-written switch first
//   2. unknown types are looked up in genericTypeRegistry
//   3. translateGeneric lifts the common attack-surface signals
//      (public_network_access, TLS, encryption, auth flags, tags)
//      into a predictable shape and carries every other field through
//      untouched so rules that target terraform-native property names
//      still match
//
// Types with deeply nested or unusual blocks (NSGs, VNets, AKS)
// continue to have hand-crafted translators because the generic lift
// wouldn't preserve their security-relevant structure.
type genericTypeSpec struct {
	tfType  string // azurerm_xxx
	armType string // Microsoft.Xxx/Yyy
	// skuField, when non-empty, names the TF attribute whose value is
	// the SKU name for this type. Enables rules that partition by SKU
	// tier (Basic / Standard / Premium) to work against ARM-style
	// snapshots produced by this generic path.
	skuField string
}

// genericTypeRegistry covers Azure resource types that are either:
//
//   * security-relevant but have simple property shapes (most common),
//     so a generic lift captures their signal completely, or
//   * niche types we want to support for completeness and future-rule
//     expansion — they carry through untouched so IaC scans don't
//     falsely show "unknown" for them.
//
// Ordering within the slice has no significance — lookup is O(1) via
// a map built at package init. The slice form is easier to review and
// to keep grouped by Azure service family.
var genericTypeRegistry = []genericTypeSpec{
	// -- Monitor / Observability --
	{"azurerm_monitor_action_group", "Microsoft.Insights/actionGroups", ""},
	{"azurerm_monitor_activity_log_alert", "Microsoft.Insights/activityLogAlerts", ""},
	{"azurerm_monitor_diagnostic_setting", "Microsoft.Insights/diagnosticSettings", ""},
	{"azurerm_monitor_metric_alert", "Microsoft.Insights/metricAlerts", ""},
	{"azurerm_monitor_scheduled_query_rules_alert", "Microsoft.Insights/scheduledQueryRules", ""},
	{"azurerm_monitor_private_link_scope", "Microsoft.Insights/privateLinkScopes", ""},
	{"azurerm_monitor_data_collection_rule", "Microsoft.Insights/dataCollectionRules", ""},
	{"azurerm_monitor_data_collection_endpoint", "Microsoft.Insights/dataCollectionEndpoints", ""},
	{"azurerm_application_insights", "Microsoft.Insights/components", ""},
	{"azurerm_application_insights_workbook", "Microsoft.Insights/workbooks", ""},
	{"azurerm_application_insights_api_key", "Microsoft.Insights/components/apiKeys", ""},
	{"azurerm_log_analytics_solution", "Microsoft.OperationsManagement/solutions", ""},
	{"azurerm_log_analytics_linked_service", "Microsoft.OperationalInsights/linkedServices", ""},
	{"azurerm_log_analytics_data_export_rule", "Microsoft.OperationalInsights/dataExports", ""},
	{"azurerm_log_analytics_saved_search", "Microsoft.OperationalInsights/savedSearches", ""},
	{"azurerm_automation_account", "Microsoft.Automation/automationAccounts", "sku_name"},
	{"azurerm_automation_runbook", "Microsoft.Automation/automationAccounts/runbooks", ""},

	// -- Backup / Recovery --
	{"azurerm_backup_container_storage_account", "Microsoft.RecoveryServices/vaults/protectionContainers", ""},
	{"azurerm_backup_policy_vm", "Microsoft.RecoveryServices/vaults/backupPolicies", ""},
	{"azurerm_backup_policy_vm_workload", "Microsoft.RecoveryServices/vaults/backupPolicies", ""},
	{"azurerm_backup_policy_file_share", "Microsoft.RecoveryServices/vaults/backupPolicies", ""},
	{"azurerm_backup_protected_vm", "Microsoft.RecoveryServices/vaults/backupProtectedItems", ""},
	{"azurerm_backup_protected_file_share", "Microsoft.RecoveryServices/vaults/backupProtectedItems", ""},
	{"azurerm_site_recovery_replication_policy", "Microsoft.RecoveryServices/vaults/replicationPolicies", ""},
	{"azurerm_site_recovery_fabric", "Microsoft.RecoveryServices/vaults/replicationFabrics", ""},
	{"azurerm_site_recovery_network_mapping", "Microsoft.RecoveryServices/vaults/replicationFabrics/replicationNetworkMappings", ""},
	{"azurerm_site_recovery_replicated_vm", "Microsoft.RecoveryServices/vaults/replicationProtectionContainers/replicationProtectedItems", ""},

	// -- Networking (long tail) --
	{"azurerm_nat_gateway", "Microsoft.Network/natGateways", ""},
	{"azurerm_nat_gateway_public_ip_association", "Microsoft.Network/natGateways/publicIPAddresses", ""},
	{"azurerm_route_table", "Microsoft.Network/routeTables", ""},
	{"azurerm_route", "Microsoft.Network/routeTables/routes", ""},
	{"azurerm_route_filter", "Microsoft.Network/routeFilters", ""},
	{"azurerm_firewall_policy", "Microsoft.Network/firewallPolicies", ""},
	{"azurerm_firewall_policy_rule_collection_group", "Microsoft.Network/firewallPolicies/ruleCollectionGroups", ""},
	{"azurerm_firewall_application_rule_collection", "Microsoft.Network/azureFirewalls/applicationRuleCollections", ""},
	{"azurerm_firewall_network_rule_collection", "Microsoft.Network/azureFirewalls/networkRuleCollections", ""},
	{"azurerm_firewall_nat_rule_collection", "Microsoft.Network/azureFirewalls/natRuleCollections", ""},
	{"azurerm_traffic_manager_profile", "Microsoft.Network/trafficmanagerprofiles", ""},
	{"azurerm_traffic_manager_azure_endpoint", "Microsoft.Network/trafficmanagerprofiles/azureEndpoints", ""},
	{"azurerm_traffic_manager_external_endpoint", "Microsoft.Network/trafficmanagerprofiles/externalEndpoints", ""},
	{"azurerm_dns_zone", "Microsoft.Network/dnsZones", ""},
	{"azurerm_dns_a_record", "Microsoft.Network/dnsZones/A", ""},
	{"azurerm_dns_aaaa_record", "Microsoft.Network/dnsZones/AAAA", ""},
	{"azurerm_dns_cname_record", "Microsoft.Network/dnsZones/CNAME", ""},
	{"azurerm_dns_txt_record", "Microsoft.Network/dnsZones/TXT", ""},
	{"azurerm_private_dns_zone", "Microsoft.Network/privateDnsZones", ""},
	{"azurerm_private_dns_zone_virtual_network_link", "Microsoft.Network/privateDnsZones/virtualNetworkLinks", ""},
	{"azurerm_private_dns_a_record", "Microsoft.Network/privateDnsZones/A", ""},
	{"azurerm_private_endpoint", "Microsoft.Network/privateEndpoints", ""},
	{"azurerm_private_link_service", "Microsoft.Network/privateLinkServices", ""},
	{"azurerm_express_route_circuit", "Microsoft.Network/expressRouteCircuits", "sku"},
	{"azurerm_express_route_gateway", "Microsoft.Network/expressRouteGateways", ""},
	{"azurerm_express_route_connection", "Microsoft.Network/expressRouteGateways/expressRouteConnections", ""},
	{"azurerm_vpn_gateway", "Microsoft.Network/vpnGateways", ""},
	{"azurerm_vpn_gateway_connection", "Microsoft.Network/vpnGateways/vpnConnections", ""},
	{"azurerm_vpn_server_configuration", "Microsoft.Network/vpnServerConfigurations", ""},
	{"azurerm_vpn_site", "Microsoft.Network/vpnSites", ""},
	{"azurerm_virtual_hub", "Microsoft.Network/virtualHubs", "sku"},
	{"azurerm_virtual_wan", "Microsoft.Network/virtualWans", ""},
	{"azurerm_virtual_network_peering", "Microsoft.Network/virtualNetworks/virtualNetworkPeerings", ""},
	{"azurerm_web_application_firewall_policy", "Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies", ""},
	{"azurerm_ddos_protection_plan", "Microsoft.Network/ddosProtectionPlans", ""},
	{"azurerm_ip_group", "Microsoft.Network/ipGroups", ""},
	{"azurerm_network_interface_security_group_association", "Microsoft.Network/networkInterfaces", ""},
	{"azurerm_subnet_network_security_group_association", "Microsoft.Network/virtualNetworks/subnets", ""},
	{"azurerm_public_ip_prefix", "Microsoft.Network/publicIPPrefixes", ""},
	{"azurerm_lb", "Microsoft.Network/loadBalancers", "sku"},
	{"azurerm_lb_rule", "Microsoft.Network/loadBalancers/loadBalancingRules", ""},
	{"azurerm_lb_probe", "Microsoft.Network/loadBalancers/probes", ""},
	{"azurerm_lb_backend_address_pool", "Microsoft.Network/loadBalancers/backendAddressPools", ""},

	// -- Data / databases (long tail) --
	{"azurerm_mssql_database", "Microsoft.Sql/servers/databases", ""},
	{"azurerm_mssql_elasticpool", "Microsoft.Sql/servers/elasticPools", ""},
	{"azurerm_mssql_managed_instance", "Microsoft.Sql/managedInstances", ""},
	{"azurerm_mssql_firewall_rule", "Microsoft.Sql/servers/firewallRules", ""},
	{"azurerm_mssql_virtual_network_rule", "Microsoft.Sql/servers/virtualNetworkRules", ""},
	{"azurerm_mssql_server_security_alert_policy", "Microsoft.Sql/servers/securityAlertPolicies", ""},
	{"azurerm_mssql_server_vulnerability_assessment", "Microsoft.Sql/servers/vulnerabilityAssessments", ""},
	{"azurerm_mssql_server_transparent_data_encryption", "Microsoft.Sql/servers/encryptionProtector", ""},
	{"azurerm_mariadb_server", "Microsoft.DBforMariaDB/servers", ""},
	{"azurerm_postgresql_flexible_server_configuration", "Microsoft.DBforPostgreSQL/flexibleServers/configurations", ""},
	{"azurerm_postgresql_flexible_server_firewall_rule", "Microsoft.DBforPostgreSQL/flexibleServers/firewallRules", ""},
	{"azurerm_mysql_flexible_server_configuration", "Microsoft.DBforMySQL/flexibleServers/configurations", ""},
	{"azurerm_mysql_flexible_server_firewall_rule", "Microsoft.DBforMySQL/flexibleServers/firewallRules", ""},
	{"azurerm_cosmosdb_sql_database", "Microsoft.DocumentDB/databaseAccounts/sqlDatabases", ""},
	{"azurerm_cosmosdb_sql_container", "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers", ""},
	{"azurerm_cosmosdb_mongo_database", "Microsoft.DocumentDB/databaseAccounts/mongodbDatabases", ""},
	{"azurerm_cosmosdb_mongo_collection", "Microsoft.DocumentDB/databaseAccounts/mongodbDatabases/collections", ""},
	{"azurerm_cosmosdb_cassandra_keyspace", "Microsoft.DocumentDB/databaseAccounts/cassandraKeyspaces", ""},
	{"azurerm_data_factory", "Microsoft.DataFactory/factories", ""},
	{"azurerm_data_factory_linked_service_azure_blob_storage", "Microsoft.DataFactory/factories/linkedservices", ""},
	{"azurerm_databricks_workspace", "Microsoft.Databricks/workspaces", "sku"},
	{"azurerm_synapse_workspace", "Microsoft.Synapse/workspaces", ""},
	{"azurerm_synapse_firewall_rule", "Microsoft.Synapse/workspaces/firewallRules", ""},
	{"azurerm_synapse_sql_pool", "Microsoft.Synapse/workspaces/sqlPools", "sku_name"},
	{"azurerm_synapse_spark_pool", "Microsoft.Synapse/workspaces/bigDataPools", ""},
	{"azurerm_stream_analytics_job", "Microsoft.StreamAnalytics/streamingjobs", ""},
	{"azurerm_stream_analytics_cluster", "Microsoft.StreamAnalytics/clusters", ""},
	{"azurerm_purview_account", "Microsoft.Purview/accounts", ""},
	{"azurerm_data_lake_analytics_account", "Microsoft.DataLakeAnalytics/accounts", ""},
	{"azurerm_data_lake_store", "Microsoft.DataLakeStore/accounts", ""},
	{"azurerm_digital_twins_instance", "Microsoft.DigitalTwins/digitalTwinsInstances", ""},

	// -- Storage (additional) --
	{"azurerm_storage_container", "Microsoft.Storage/storageAccounts/blobServices/containers", ""},
	{"azurerm_storage_blob", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs", ""},
	{"azurerm_storage_queue", "Microsoft.Storage/storageAccounts/queueServices/queues", ""},
	{"azurerm_storage_share", "Microsoft.Storage/storageAccounts/fileServices/shares", ""},
	{"azurerm_storage_table", "Microsoft.Storage/storageAccounts/tableServices/tables", ""},
	{"azurerm_storage_account_network_rules", "Microsoft.Storage/storageAccounts/networkRuleSet", ""},
	{"azurerm_storage_data_lake_gen2_filesystem", "Microsoft.Storage/storageAccounts/blobServices/containers", ""},
	{"azurerm_storage_management_policy", "Microsoft.Storage/storageAccounts/managementPolicies", ""},
	{"azurerm_storage_encryption_scope", "Microsoft.Storage/storageAccounts/encryptionScopes", ""},
	{"azurerm_netapp_account", "Microsoft.NetApp/netAppAccounts", ""},
	{"azurerm_netapp_pool", "Microsoft.NetApp/netAppAccounts/capacityPools", ""},
	{"azurerm_netapp_volume", "Microsoft.NetApp/netAppAccounts/capacityPools/volumes", ""},

	// -- Compute (long tail) --
	{"azurerm_linux_virtual_machine_scale_set", "Microsoft.Compute/virtualMachineScaleSets", ""},
	{"azurerm_windows_virtual_machine_scale_set", "Microsoft.Compute/virtualMachineScaleSets", ""},
	{"azurerm_virtual_machine_scale_set_extension", "Microsoft.Compute/virtualMachineScaleSets/extensions", ""},
	{"azurerm_virtual_machine_extension", "Microsoft.Compute/virtualMachines/extensions", ""},
	{"azurerm_availability_set", "Microsoft.Compute/availabilitySets", ""},
	{"azurerm_proximity_placement_group", "Microsoft.Compute/proximityPlacementGroups", ""},
	{"azurerm_shared_image_gallery", "Microsoft.Compute/galleries", ""},
	{"azurerm_shared_image", "Microsoft.Compute/galleries/images", ""},
	{"azurerm_shared_image_version", "Microsoft.Compute/galleries/images/versions", ""},
	{"azurerm_image", "Microsoft.Compute/images", ""},
	{"azurerm_snapshot", "Microsoft.Compute/snapshots", ""},
	{"azurerm_dedicated_host", "Microsoft.Compute/hostGroups/hosts", ""},
	{"azurerm_dedicated_host_group", "Microsoft.Compute/hostGroups", ""},
	{"azurerm_disk_encryption_set", "Microsoft.Compute/diskEncryptionSets", ""},
	{"azurerm_managed_disk_sas_token", "Microsoft.Compute/disks", ""},
	{"azurerm_ssh_public_key", "Microsoft.Compute/sshPublicKeys", ""},
	{"azurerm_capacity_reservation", "Microsoft.Compute/capacityReservationGroups/capacityReservations", ""},
	{"azurerm_capacity_reservation_group", "Microsoft.Compute/capacityReservationGroups", ""},

	// -- Containers / K8s --
	{"azurerm_kubernetes_cluster_node_pool", "Microsoft.ContainerService/managedClusters/agentPools", ""},
	{"azurerm_kubernetes_cluster_extension", "Microsoft.KubernetesConfiguration/extensions", ""},
	{"azurerm_container_group", "Microsoft.ContainerInstance/containerGroups", ""},
	{"azurerm_container_app_environment", "Microsoft.App/managedEnvironments", ""},
	{"azurerm_container_app_environment_certificate", "Microsoft.App/managedEnvironments/certificates", ""},
	{"azurerm_container_registry_scope_map", "Microsoft.ContainerRegistry/registries/scopeMaps", ""},
	{"azurerm_container_registry_token", "Microsoft.ContainerRegistry/registries/tokens", ""},
	{"azurerm_container_registry_webhook", "Microsoft.ContainerRegistry/registries/webhooks", ""},
	{"azurerm_service_fabric_cluster", "Microsoft.ServiceFabric/clusters", ""},
	{"azurerm_service_fabric_managed_cluster", "Microsoft.ServiceFabric/managedClusters", ""},
	{"azurerm_spring_cloud_service", "Microsoft.AppPlatform/Spring", "sku_name"},
	{"azurerm_spring_cloud_app", "Microsoft.AppPlatform/Spring/apps", ""},

	// -- AI / ML --
	{"azurerm_machine_learning_workspace", "Microsoft.MachineLearningServices/workspaces", ""},
	{"azurerm_machine_learning_compute_cluster", "Microsoft.MachineLearningServices/workspaces/computes", ""},
	{"azurerm_machine_learning_compute_instance", "Microsoft.MachineLearningServices/workspaces/computes", ""},
	{"azurerm_machine_learning_inference_cluster", "Microsoft.MachineLearningServices/workspaces/computes", ""},
	{"azurerm_bot_service_azure_bot", "Microsoft.BotService/botServices", ""},
	{"azurerm_bot_channels_registration", "Microsoft.BotService/botServices", ""},

	// -- App services / integration --
	{"azurerm_service_plan", "Microsoft.Web/serverfarms", "sku_name"},
	{"azurerm_app_service_plan", "Microsoft.Web/serverfarms", "sku.0.tier"},
	{"azurerm_app_service_custom_hostname_binding", "Microsoft.Web/sites/hostNameBindings", ""},
	{"azurerm_app_service_certificate", "Microsoft.Web/certificates", ""},
	{"azurerm_app_service_environment_v3", "Microsoft.Web/hostingEnvironments", ""},
	{"azurerm_app_configuration", "Microsoft.AppConfiguration/configurationStores", "sku"},
	{"azurerm_app_configuration_feature", "Microsoft.AppConfiguration/configurationStores/keyValues", ""},
	{"azurerm_logic_app_workflow", "Microsoft.Logic/workflows", ""},
	{"azurerm_logic_app_standard", "Microsoft.Web/sites", ""},
	{"azurerm_static_site", "Microsoft.Web/staticSites", "sku_tier"},
	{"azurerm_signalr_service", "Microsoft.SignalRService/SignalR", "sku.0.name"},
	{"azurerm_web_pubsub", "Microsoft.SignalRService/WebPubSub", "sku.0.name"},
	{"azurerm_api_management", "Microsoft.ApiManagement/service", "sku_name"},
	{"azurerm_api_management_api", "Microsoft.ApiManagement/service/apis", ""},
	{"azurerm_api_management_backend", "Microsoft.ApiManagement/service/backends", ""},
	{"azurerm_api_management_policy", "Microsoft.ApiManagement/service/policies", ""},
	{"azurerm_api_management_product", "Microsoft.ApiManagement/service/products", ""},
	{"azurerm_api_management_subscription", "Microsoft.ApiManagement/service/subscriptions", ""},

	// -- Messaging / events (long tail) --
	{"azurerm_servicebus_topic", "Microsoft.ServiceBus/namespaces/topics", ""},
	{"azurerm_servicebus_queue", "Microsoft.ServiceBus/namespaces/queues", ""},
	{"azurerm_servicebus_subscription", "Microsoft.ServiceBus/namespaces/topics/subscriptions", ""},
	{"azurerm_servicebus_namespace_authorization_rule", "Microsoft.ServiceBus/namespaces/authorizationRules", ""},
	{"azurerm_eventhub", "Microsoft.EventHub/namespaces/eventhubs", ""},
	{"azurerm_eventhub_consumer_group", "Microsoft.EventHub/namespaces/eventhubs/consumergroups", ""},
	{"azurerm_eventhub_authorization_rule", "Microsoft.EventHub/namespaces/eventhubs/authorizationRules", ""},
	{"azurerm_eventgrid_topic", "Microsoft.EventGrid/topics", ""},
	{"azurerm_eventgrid_event_subscription", "Microsoft.EventGrid/eventSubscriptions", ""},
	{"azurerm_eventgrid_domain", "Microsoft.EventGrid/domains", ""},
	{"azurerm_eventgrid_system_topic", "Microsoft.EventGrid/systemTopics", ""},
	{"azurerm_iothub", "Microsoft.Devices/IotHubs", "sku.0.name"},
	{"azurerm_iothub_consumer_group", "Microsoft.Devices/IotHubs/eventHubEndpoints/ConsumerGroups", ""},
	{"azurerm_iothub_dps", "Microsoft.Devices/provisioningServices", "sku.0.name"},
	{"azurerm_iothub_endpoint_eventhub", "Microsoft.Devices/IotHubs", ""},
	{"azurerm_iothub_route", "Microsoft.Devices/IotHubs/routes", ""},
	{"azurerm_relay_namespace", "Microsoft.Relay/namespaces", ""},
	{"azurerm_notification_hub", "Microsoft.NotificationHubs/namespaces/notificationHubs", ""},
	{"azurerm_notification_hub_namespace", "Microsoft.NotificationHubs/namespaces", ""},

	// -- Security / governance --
	{"azurerm_sentinel_alert_rule_ms_security_incident", "Microsoft.SecurityInsights/alertRules", ""},
	{"azurerm_sentinel_alert_rule_scheduled", "Microsoft.SecurityInsights/alertRules", ""},
	{"azurerm_sentinel_data_connector_azure_active_directory", "Microsoft.SecurityInsights/dataConnectors", ""},
	{"azurerm_sentinel_log_analytics_workspace_onboarding", "Microsoft.SecurityInsights/onboardingStates", ""},
	{"azurerm_security_center_contact", "Microsoft.Security/securityContacts", ""},
	{"azurerm_security_center_auto_provisioning", "Microsoft.Security/autoProvisioningSettings", ""},
	{"azurerm_security_center_setting", "Microsoft.Security/settings", ""},
	{"azurerm_security_center_subscription_pricing", "Microsoft.Security/pricings", ""},
	{"azurerm_security_center_workspace", "Microsoft.Security/workspaceSettings", ""},
	{"azurerm_advanced_threat_protection", "Microsoft.Security/advancedThreatProtectionSettings", ""},
	{"azurerm_policy_assignment", "Microsoft.Authorization/policyAssignments", ""},
	{"azurerm_policy_definition", "Microsoft.Authorization/policyDefinitions", ""},
	{"azurerm_policy_set_definition", "Microsoft.Authorization/policySetDefinitions", ""},
	{"azurerm_policy_exemption", "Microsoft.Authorization/policyExemptions", ""},
	{"azurerm_role_assignment", "Microsoft.Authorization/roleAssignments", ""},
	{"azurerm_role_definition", "Microsoft.Authorization/roleDefinitions", ""},
	{"azurerm_user_assigned_identity", "Microsoft.ManagedIdentity/userAssignedIdentities", ""},
	{"azurerm_key_vault_access_policy", "Microsoft.KeyVault/vaults/accessPolicies", ""},
	{"azurerm_key_vault_certificate", "Microsoft.KeyVault/vaults/certificates", ""},
	{"azurerm_key_vault_secret", "Microsoft.KeyVault/vaults/secrets", ""},
	{"azurerm_key_vault_key", "Microsoft.KeyVault/vaults/keys", ""},
	{"azurerm_key_vault_managed_hardware_security_module", "Microsoft.KeyVault/managedHSMs", ""},
	{"azurerm_management_group", "Microsoft.Management/managementGroups", ""},
	{"azurerm_management_group_policy_assignment", "Microsoft.Authorization/policyAssignments", ""},
	{"azurerm_resource_group", "Microsoft.Resources/resourceGroups", ""},
	{"azurerm_resource_group_template_deployment", "Microsoft.Resources/deployments", ""},
	{"azurerm_resource_policy_assignment", "Microsoft.Authorization/policyAssignments", ""},
}

// genericTypeIndex is the O(1) lookup table built from
// genericTypeRegistry at package init.
var genericTypeIndex = func() map[string]genericTypeSpec {
	m := make(map[string]genericTypeSpec, len(genericTypeRegistry))
	for _, s := range genericTypeRegistry {
		m[s.tfType] = s
	}
	return m
}()

// genericTypeLookup returns the registered spec for a TF type, or
// (zero-value, false) if the type is not in the registry.
func genericTypeLookup(tfType string) (genericTypeSpec, bool) {
	s, ok := genericTypeIndex[tfType]
	return s, ok
}

// translateGeneric lifts the common attack-surface signals from a TF
// resource and emits an AzureResource with the canonical Microsoft.*
// type. The goal is not 1:1 fidelity — hand-written translators
// remain the right answer for complex shapes — but rather "if a
// policy rule matches by ARM type and one of these common knobs, it
// fires against this generic snapshot entry." Rules that inspect
// resource-specific deep structure will skip generically-emitted
// entries, which is safe: the rule's criterion is not satisfied, no
// false positive is produced.
func translateGeneric(rc ResourceChange, spec genericTypeSpec) models.AzureResource {
	after := rc.Change.After
	if after == nil {
		after = map[string]interface{}{}
	}

	// Common attack-surface fields — normalised to ARM property names
	// so rules written against live Resource Graph output match.
	props := map[string]interface{}{}
	if v, ok := after["public_network_access_enabled"]; ok {
		b, _ := v.(bool)
		props["publicNetworkAccess"] = enabledDisabled(b)
	}
	if v := stringFrom(after, "minimum_tls_version"); v != "" {
		props["minimumTlsVersion"] = v
	}
	if v := stringFrom(after, "min_tls_version"); v != "" {
		props["minimumTlsVersion"] = v
	}
	if v, ok := after["local_authentication_enabled"]; ok {
		if b, _ := v.(bool); !b {
			props["disableLocalAuth"] = true
		}
	}
	if v, ok := after["local_auth_enabled"]; ok {
		if b, _ := v.(bool); !b {
			props["disableLocalAuth"] = true
		}
	}
	if v, ok := after["zone_redundant"]; ok {
		props["zoneRedundant"] = v
	}

	// Carry every original TF field through so IaC-written rules that
	// target terraform property names (rather than normalised ARM
	// names) can still match.
	for k, v := range after {
		if _, exists := props[k]; exists {
			continue
		}
		props[k] = v
	}

	skuStr := ""
	if spec.skuField != "" {
		skuStr = resolveSKUField(after, spec.skuField)
	} else {
		// Best-effort: common TF field names for SKU.
		for _, candidate := range []string{"sku", "sku_name", "sku_tier"} {
			if v := stringFrom(after, candidate); v != "" {
				skuStr = v
				break
			}
		}
	}

	return models.AzureResource{
		ID:            synthesizeID(rc, spec.armType),
		Name:          stringFrom(after, "name"),
		Type:          spec.armType,
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
		SKU:           skuStr,
	}
}

// resolveSKUField reads a SKU value from a possibly-nested TF field
// spec like "sku.0.name" (typical of provider v3 block schemas).
func resolveSKUField(m map[string]interface{}, spec string) string {
	parts := strings.Split(spec, ".")
	var cur interface{} = m
	for _, p := range parts {
		switch cv := cur.(type) {
		case map[string]interface{}:
			cur = cv[p]
		case []interface{}:
			// index into list (p should be numeric)
			idx := 0
			for _, c := range p {
				idx = idx*10 + int(c-'0')
			}
			if idx >= len(cv) {
				return ""
			}
			cur = cv[idx]
		default:
			return ""
		}
		if cur == nil {
			return ""
		}
	}
	if s, ok := cur.(string); ok {
		return s
	}
	return ""
}
