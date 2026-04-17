package iac

import (
	"fmt"
	"strings"
	"time"

	"github.com/vatsayanvivek/argus/internal/models"
)

// Translate converts a parsed terraform plan into a synthetic
// models.AzureSnapshot that the existing OPA/Rego engine can evaluate.
// Each Terraform azurerm_* resource is mapped to the equivalent
// Microsoft.* ARM resource type and its property names are normalised
// so policies written against live Azure Resource Graph output still
// fire against pre-deployment state.
//
// A resource type the translator does not understand is carried through
// with its raw terraform type and values unchanged; rules that match on
// the Microsoft.* type simply will not evaluate those entries, which is
// the safe behaviour for pre-deployment.
func Translate(plan *Plan, pseudoSubscriptionID, pseudoTenantID string) *models.AzureSnapshot {
	if plan == nil {
		return &models.AzureSnapshot{}
	}

	snap := &models.AzureSnapshot{
		SubscriptionID:   pseudoSubscriptionID,
		SubscriptionName: "terraform-plan",
		TenantID:         pseudoTenantID,
		ScanTime:         time.Now().UTC(),
		CollectionMode:   "iac",
		DefenderPlans:    map[string]string{},
		DiagnosticSettings: map[string]bool{},
	}

	var nsgs []models.NetworkSecurityGroup
	var vnets []models.VirtualNetwork
	var subnets []models.Subnet

	for _, rc := range plan.PlannedResources() {
		switch rc.Type {

		case "azurerm_storage_account":
			snap.Resources = append(snap.Resources, translateStorageAccount(rc))

		case "azurerm_key_vault":
			snap.Resources = append(snap.Resources, translateKeyVault(rc))

		case "azurerm_mssql_server", "azurerm_sql_server":
			snap.Resources = append(snap.Resources, translateSQLServer(rc))

		case "azurerm_postgresql_server":
			snap.Resources = append(snap.Resources, translatePostgresServer(rc))

		case "azurerm_postgresql_flexible_server":
			snap.Resources = append(snap.Resources, translatePostgresFlexServer(rc))

		case "azurerm_mysql_server":
			snap.Resources = append(snap.Resources, translateMySQLServer(rc))

		case "azurerm_mysql_flexible_server":
			snap.Resources = append(snap.Resources, translateMySQLFlexServer(rc))

		case "azurerm_cosmosdb_account":
			snap.Resources = append(snap.Resources, translateCosmosDB(rc))

		case "azurerm_kubernetes_cluster":
			snap.Resources = append(snap.Resources, translateAKSCluster(rc))

		case "azurerm_container_registry":
			snap.Resources = append(snap.Resources, translateContainerRegistry(rc))

		case "azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app":
			snap.Resources = append(snap.Resources, translateAppService(rc, "app"))

		case "azurerm_function_app", "azurerm_linux_function_app", "azurerm_windows_function_app":
			snap.Resources = append(snap.Resources, translateAppService(rc, "functionapp"))

		case "azurerm_virtual_machine", "azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine":
			snap.Resources = append(snap.Resources, translateVM(rc))

		case "azurerm_public_ip":
			snap.Resources = append(snap.Resources, translatePublicIP(rc))

		case "azurerm_network_security_group":
			nsg := translateNSG(rc)
			nsgs = append(nsgs, nsg)
			snap.Resources = append(snap.Resources, models.AzureResource{
				ID:            nsg.ID,
				Name:          nsg.Name,
				Type:          "Microsoft.Network/networkSecurityGroups",
				ResourceGroup: stringFrom(rc.Change.After, "resource_group_name"),
				Location:      stringFrom(rc.Change.After, "location"),
				Properties:    nsgProperties(nsg),
			})

		case "azurerm_virtual_network":
			vnet := translateVNet(rc)
			vnets = append(vnets, vnet)
			snap.Resources = append(snap.Resources, models.AzureResource{
				ID:            vnet.ID,
				Name:          vnet.Name,
				Type:          "Microsoft.Network/virtualNetworks",
				ResourceGroup: vnet.ResourceGroup,
				Location:      stringFrom(rc.Change.After, "location"),
				Properties: map[string]interface{}{
					"addressSpace":     map[string]interface{}{"addressPrefixes": toInterfaceSlice(vnet.AddressSpace)},
					"enableDdosProtection": vnet.DDoSEnabled,
				},
			})

		case "azurerm_subnet":
			subnets = append(subnets, translateSubnet(rc))

		case "azurerm_redis_cache":
			snap.Resources = append(snap.Resources, translateRedisCache(rc))

		case "azurerm_servicebus_namespace":
			snap.Resources = append(snap.Resources, translateServiceBusNamespace(rc))

		case "azurerm_eventhub_namespace":
			snap.Resources = append(snap.Resources, translateEventHubNamespace(rc))

		case "azurerm_log_analytics_workspace":
			snap.Resources = append(snap.Resources, translateLogAnalyticsWorkspace(rc))

		case "azurerm_application_gateway":
			snap.Resources = append(snap.Resources, translateApplicationGateway(rc))

		case "azurerm_frontdoor", "azurerm_cdn_frontdoor_profile":
			snap.Resources = append(snap.Resources, translateFrontDoor(rc))

		case "azurerm_firewall":
			snap.Resources = append(snap.Resources, translateAzureFirewall(rc))

		case "azurerm_bastion_host":
			snap.Resources = append(snap.Resources, translateBastionHost(rc))

		case "azurerm_cognitive_account":
			snap.Resources = append(snap.Resources, translateCognitiveAccount(rc))

		case "azurerm_managed_disk":
			snap.Resources = append(snap.Resources, translateManagedDisk(rc))

		case "azurerm_recovery_services_vault":
			snap.Resources = append(snap.Resources, translateRecoveryServicesVault(rc))

		case "azurerm_network_watcher":
			snap.Resources = append(snap.Resources, translateNetworkWatcher(rc))

		case "azurerm_virtual_network_gateway":
			snap.Resources = append(snap.Resources, translateVirtualNetworkGateway(rc))

		case "azurerm_container_app":
			snap.Resources = append(snap.Resources, translateContainerApp(rc))

		case "azurerm_search_service":
			snap.Resources = append(snap.Resources, translateSearchService(rc))

		default:
			// Before falling back to the raw passthrough, consult the
			// generic type registry. It covers ~120 additional Azure
			// resource types with simple property shapes, so we reach
			// Checkov-class coverage (~150 types total) without a
			// bespoke handler for each one. Types not in the registry
			// (bleeding-edge TF provider additions, third-party
			// providers) pass through as-is.
			if spec, ok := genericTypeLookup(rc.Type); ok {
				snap.Resources = append(snap.Resources, translateGeneric(rc, spec))
				break
			}
			snap.Resources = append(snap.Resources, models.AzureResource{
				ID:            rc.Address,
				Name:          rc.Name,
				Type:          rc.Type,
				ResourceGroup: stringFrom(rc.Change.After, "resource_group_name"),
				Location:      stringFrom(rc.Change.After, "location"),
				Properties:    rc.Change.After,
				Tags:          stringMapFrom(rc.Change.After, "tags"),
			})
		}
	}

	snap.NetworkTopology = models.NetworkSnapshot{
		VNets:   vnets,
		Subnets: subnets,
		NSGs:    nsgs,
	}

	return snap
}

// ----------------------------------------------------------------------
// Per-type translators
// ----------------------------------------------------------------------

func translateStorageAccount(rc ResourceChange) models.AzureResource {
	after := rc.Change.After

	// Terraform uses allow_nested_items_to_be_public for the property Azure
	// calls allowBlobPublicAccess. The default is true unless explicitly
	// set to false, which matches the Azure Resource Graph default.
	allowPublic := boolFrom(after, "allow_nested_items_to_be_public", true)
	httpsOnly := boolFrom(after, "enable_https_traffic_only", true)
	minTLS := stringFrom(after, "min_tls_version")
	if minTLS == "" {
		minTLS = "TLS1_0" // terraform provider default
	}

	// Network ACLs come in as a list block; unwrap the first entry.
	netRules := firstMap(after, "network_rules")
	defaultAction := stringFrom(netRules, "default_action")
	if defaultAction == "" {
		defaultAction = "Allow" // terraform provider default
	}

	// Public network access is an enum string in Azure ("Enabled" /
	// "Disabled"). The TF boolean `public_network_access_enabled` became
	// authoritative in azurerm 3.x — default is true.
	publicAccessEnabled := boolFrom(after, "public_network_access_enabled", true)
	publicAccessStr := "Enabled"
	if !publicAccessEnabled {
		publicAccessStr = "Disabled"
	}

	blobProps := firstMap(after, "blob_properties")
	versioningEnabled := boolFrom(blobProps, "versioning_enabled", false)

	props := map[string]interface{}{
		"allowBlobPublicAccess":       allowPublic,
		"supportsHttpsTrafficOnly":    httpsOnly,
		"minimumTlsVersion":           minTLS,
		"publicNetworkAccess":         publicAccessStr,
		"isVersioningEnabled":         versioningEnabled,
		"allowSharedKeyAccess":        boolFrom(after, "shared_access_key_enabled", true),
		"networkAcls": map[string]interface{}{
			"defaultAction": defaultAction,
			"bypass":        stringFrom(netRules, "bypass"),
		},
	}

	// Preserve terraform-native field names too so IaC-specific rules
	// written against TF idioms also match.
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}

	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.Storage/storageAccounts"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.Storage/storageAccounts",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
		SKU:           stringFrom(firstMap(after, "sku"), "name"),
	}
}

func translateKeyVault(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	props := map[string]interface{}{
		"enablePurgeProtection":     boolFrom(after, "purge_protection_enabled", false),
		"enableSoftDelete":          true, // soft delete is mandatory on Key Vault since 2020
		"softDeleteRetentionInDays": intFrom(after, "soft_delete_retention_days", 7),
		"enableRbacAuthorization":   boolFrom(after, "enable_rbac_authorization", false),
		"publicNetworkAccess":       enabledDisabled(boolFrom(after, "public_network_access_enabled", true)),
	}

	if net := firstMap(after, "network_acls"); len(net) > 0 {
		props["networkAcls"] = map[string]interface{}{
			"defaultAction": stringFrom(net, "default_action"),
			"bypass":        stringFrom(net, "bypass"),
		}
	}

	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}

	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.KeyVault/vaults"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.KeyVault/vaults",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
	}
}

func translateSQLServer(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	props := map[string]interface{}{
		"minimalTlsVersion":     stringFrom(after, "minimum_tls_version"),
		"publicNetworkAccess":   enabledDisabled(boolFrom(after, "public_network_access_enabled", true)),
		"administratorLogin":    stringFrom(after, "administrator_login"),
		"version":               stringFrom(after, "version"),
	}
	if azAdmin := firstMap(after, "azuread_administrator"); len(azAdmin) > 0 {
		props["azureADOnlyAuthentication"] = boolFrom(azAdmin, "azuread_authentication_only", false)
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.Sql/servers"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.Sql/servers",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
	}
}

func translatePostgresServer(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	props := map[string]interface{}{
		"sslEnforcement":      stringFrom(after, "ssl_enforcement_enabled"),
		"minimalTlsVersion":   stringFrom(after, "ssl_minimal_tls_version_enforced"),
		"publicNetworkAccess": enabledDisabled(boolFrom(after, "public_network_access_enabled", true)),
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.DBforPostgreSQL/servers"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.DBforPostgreSQL/servers",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
	}
}

func translateMySQLServer(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	props := map[string]interface{}{
		"sslEnforcement":      stringFrom(after, "ssl_enforcement_enabled"),
		"minimalTlsVersion":   stringFrom(after, "ssl_minimal_tls_version_enforced"),
		"publicNetworkAccess": enabledDisabled(boolFrom(after, "public_network_access_enabled", true)),
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.DBforMySQL/servers"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.DBforMySQL/servers",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
	}
}

func translateCosmosDB(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	props := map[string]interface{}{
		"publicNetworkAccess":      enabledDisabled(boolFrom(after, "public_network_access_enabled", true)),
		"enableAutomaticFailover":  boolFrom(after, "enable_automatic_failover", false),
		"disableLocalAuth":         boolFrom(after, "local_authentication_disabled", false),
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.DocumentDB/databaseAccounts"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.DocumentDB/databaseAccounts",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
	}
}

func translateAKSCluster(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	apiProfile := firstMap(after, "api_server_access_profile")
	netProfile := firstMap(after, "network_profile")

	props := map[string]interface{}{
		"apiServerAccessProfile": map[string]interface{}{
			"enablePrivateCluster": boolFrom(after, "private_cluster_enabled", false),
			"authorizedIPRanges":   stringSliceFrom(apiProfile, "authorized_ip_ranges"),
		},
		"enableRBAC":             boolFrom(after, "role_based_access_control_enabled", true),
		"aadProfile":             aadProfileFrom(firstMap(after, "azure_active_directory_role_based_access_control")),
		"networkProfile": map[string]interface{}{
			"networkPlugin": stringFrom(netProfile, "network_plugin"),
			"networkPolicy": stringFrom(netProfile, "network_policy"),
		},
		"addonProfiles": map[string]interface{}{
			"azurepolicy": map[string]interface{}{
				"enabled": boolFrom(after, "azure_policy_enabled", false),
			},
			"omsAgent": map[string]interface{}{
				"enabled": firstMap(after, "oms_agent") != nil,
			},
		},
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.ContainerService/managedClusters"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.ContainerService/managedClusters",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
	}
}

func translateContainerRegistry(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	props := map[string]interface{}{
		"adminUserEnabled":      boolFrom(after, "admin_enabled", false),
		"publicNetworkAccess":   enabledDisabled(boolFrom(after, "public_network_access_enabled", true)),
		"zoneRedundancy":        enabledDisabled(boolFrom(after, "zone_redundancy_enabled", false)),
		"anonymousPullEnabled":  boolFrom(after, "anonymous_pull_enabled", false),
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.ContainerRegistry/registries"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.ContainerRegistry/registries",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
		SKU:           stringFrom(after, "sku"),
	}
}

func translateAppService(rc ResourceChange, kind string) models.AzureResource {
	after := rc.Change.After
	siteCfg := firstMap(after, "site_config")
	props := map[string]interface{}{
		"httpsOnly":                 boolFrom(after, "https_only", false),
		"clientCertEnabled":         boolFrom(after, "client_cert_enabled", false),
		"siteConfig": map[string]interface{}{
			"minTlsVersion":  stringFrom(siteCfg, "minimum_tls_version"),
			"ftpsState":      stringFrom(siteCfg, "ftps_state"),
			"http20Enabled":  boolFrom(siteCfg, "http2_enabled", false),
			"remoteDebuggingEnabled": boolFrom(siteCfg, "remote_debugging_enabled", false),
		},
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.Web/sites"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.Web/sites",
		Kind:          kind,
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
	}
}

func translateVM(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	identity := firstMap(after, "identity")
	props := map[string]interface{}{
		"osProfile": map[string]interface{}{
			"computerName":  stringFrom(after, "computer_name"),
			"adminUsername": stringFrom(after, "admin_username"),
			// Password auth disabled = SSH-key only (good posture)
			"disablePasswordAuthentication": boolFrom(after, "disable_password_authentication", true),
		},
		"hasManagedIdentity": identity != nil,
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.Compute/virtualMachines"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.Compute/virtualMachines",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
	}
}

func translatePublicIP(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	props := map[string]interface{}{
		"publicIPAllocationMethod": stringFrom(after, "allocation_method"),
		"publicIPAddressVersion":   stringFrom(after, "ip_version"),
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.Network/publicIPAddresses"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.Network/publicIPAddresses",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
		SKU:           stringFrom(after, "sku"),
	}
}

func translateNSG(rc ResourceChange) models.NetworkSecurityGroup {
	after := rc.Change.After
	nsg := models.NetworkSecurityGroup{
		ID:            synthesizeID(rc, "Microsoft.Network/networkSecurityGroups"),
		Name:          stringFrom(after, "name"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
	}
	for _, raw := range sliceOfMapsFrom(after, "security_rule") {
		rule := models.NSGRule{
			Name:                     stringFrom(raw, "name"),
			Protocol:                 stringFrom(raw, "protocol"),
			Direction:                stringFrom(raw, "direction"),
			Access:                   stringFrom(raw, "access"),
			Priority:                 intFrom(raw, "priority", 0),
			SourceAddressPrefix:      stringFrom(raw, "source_address_prefix"),
			SourcePortRange:          stringFrom(raw, "source_port_range"),
			DestinationAddressPrefix: stringFrom(raw, "destination_address_prefix"),
			DestinationPortRange:     stringFrom(raw, "destination_port_range"),
		}
		if strings.EqualFold(rule.Direction, "Inbound") {
			nsg.InboundRules = append(nsg.InboundRules, rule)
		} else {
			nsg.OutboundRules = append(nsg.OutboundRules, rule)
		}
	}
	return nsg
}

func translateVNet(rc ResourceChange) models.VirtualNetwork {
	after := rc.Change.After
	return models.VirtualNetwork{
		ID:            synthesizeID(rc, "Microsoft.Network/virtualNetworks"),
		Name:          stringFrom(after, "name"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		AddressSpace:  stringSliceFrom(after, "address_space"),
	}
}

func translateSubnet(rc ResourceChange) models.Subnet {
	after := rc.Change.After
	nsgID := stringFrom(after, "network_security_group_id")
	return models.Subnet{
		ID:     synthesizeID(rc, "Microsoft.Network/virtualNetworks/subnets"),
		Name:   stringFrom(after, "name"),
		VNetID: stringFrom(after, "virtual_network_name"),
		CIDR:   firstString(stringSliceFrom(after, "address_prefixes")),
		NSGID:  nsgID,
		HasNSG: nsgID != "",
	}
}

func nsgProperties(nsg models.NetworkSecurityGroup) map[string]interface{} {
	ruleFn := func(rules []models.NSGRule) []interface{} {
		out := make([]interface{}, 0, len(rules))
		for _, r := range rules {
			out = append(out, map[string]interface{}{
				"name":                       r.Name,
				"protocol":                   r.Protocol,
				"direction":                  r.Direction,
				"access":                     r.Access,
				"priority":                   r.Priority,
				"sourceAddressPrefix":        r.SourceAddressPrefix,
				"sourcePortRange":            r.SourcePortRange,
				"destinationAddressPrefix":   r.DestinationAddressPrefix,
				"destinationPortRange":       r.DestinationPortRange,
			})
		}
		return out
	}
	return map[string]interface{}{
		"securityRules": append(ruleFn(nsg.InboundRules), ruleFn(nsg.OutboundRules)...),
	}
}

// translatePostgresFlexServer — Microsoft.DBforPostgreSQL/flexibleServers.
// Flexible is a separate ARM type from the legacy single-server product
// and has a different property shape (authentication block, HA block,
// sslmode removed in favour of require_secure_transport at the server
// parameter level, etc.). Keeping it in its own translator means policy
// rules targeting flexibleServers see the correct, normalised shape.
func translatePostgresFlexServer(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	auth := firstMap(after, "authentication")
	props := map[string]interface{}{
		"publicNetworkAccess":     enabledDisabled(boolFrom(after, "public_network_access_enabled", true)),
		"administratorLogin":      stringFrom(after, "administrator_login"),
		"version":                 stringFrom(after, "version"),
		"authConfig": map[string]interface{}{
			"activeDirectoryAuth": boolFrom(auth, "active_directory_auth_enabled", false),
			"passwordAuth":        boolFrom(auth, "password_auth_enabled", true),
		},
		"storageMB":         intFrom(after, "storage_mb", 0),
		"backupRetentionDays": intFrom(after, "backup_retention_days", 7),
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.DBforPostgreSQL/flexibleServers"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.DBforPostgreSQL/flexibleServers",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
	}
}

// translateMySQLFlexServer — Microsoft.DBforMySQL/flexibleServers.
// Same rationale as PostgreSQL flex: distinct ARM type with a different
// property schema (no ssl_enforcement_enabled — replaced by tls_version
// in the server parameters).
func translateMySQLFlexServer(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	props := map[string]interface{}{
		"publicNetworkAccess":   enabledDisabled(boolFrom(after, "public_network_access_enabled", true)),
		"administratorLogin":    stringFrom(after, "administrator_login"),
		"version":               stringFrom(after, "version"),
		"storageSizeGB":         intFrom(after, "storage.0.size_gb", 0),
		"backupRetentionDays":   intFrom(after, "backup_retention_days", 7),
		"geoRedundantBackup":    boolFrom(after, "geo_redundant_backup_enabled", false),
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.DBforMySQL/flexibleServers"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.DBforMySQL/flexibleServers",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
	}
}

// translateRedisCache — Microsoft.Cache/Redis. Rules look at TLS
// minimum, non-SSL port state, and public network access.
func translateRedisCache(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	props := map[string]interface{}{
		"minimumTlsVersion":         stringFrom(after, "minimum_tls_version"),
		"enableNonSslPort":          boolFrom(after, "enable_non_ssl_port", false),
		"publicNetworkAccess":       enabledDisabled(boolFrom(after, "public_network_access_enabled", true)),
		"redisVersion":              stringFrom(after, "redis_version"),
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.Cache/Redis"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.Cache/Redis",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
		SKU:           stringFrom(after, "sku_name"),
	}
}

// translateServiceBusNamespace — Microsoft.ServiceBus/namespaces.
func translateServiceBusNamespace(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	props := map[string]interface{}{
		"minimumTlsVersion":       stringFrom(after, "minimum_tls_version"),
		"publicNetworkAccess":     enabledDisabled(boolFrom(after, "public_network_access_enabled", true)),
		"localAuthEnabled":        boolFrom(after, "local_auth_enabled", true),
		"zoneRedundant":           boolFrom(after, "zone_redundant", false),
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.ServiceBus/namespaces"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.ServiceBus/namespaces",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
		SKU:           stringFrom(after, "sku"),
	}
}

// translateEventHubNamespace — Microsoft.EventHub/namespaces.
func translateEventHubNamespace(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	props := map[string]interface{}{
		"minimumTlsVersion":     stringFrom(after, "minimum_tls_version"),
		"publicNetworkAccess":   enabledDisabled(boolFrom(after, "public_network_access_enabled", true)),
		"localAuthEnabled":      boolFrom(after, "local_authentication_enabled", true),
		"autoInflateEnabled":    boolFrom(after, "auto_inflate_enabled", false),
		"zoneRedundant":         boolFrom(after, "zone_redundant", false),
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.EventHub/namespaces"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.EventHub/namespaces",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
		SKU:           stringFrom(after, "sku"),
	}
}

// translateLogAnalyticsWorkspace — Microsoft.OperationalInsights/workspaces.
// Key signals: retention (short retention blinds incident response),
// daily quota, internet ingestion / query enabled.
func translateLogAnalyticsWorkspace(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	props := map[string]interface{}{
		"retentionInDays":                intFrom(after, "retention_in_days", 30),
		"dailyQuotaGb":                   after["daily_quota_gb"],
		"internetIngestionEnabled":       boolFrom(after, "internet_ingestion_enabled", true),
		"internetQueryEnabled":           boolFrom(after, "internet_query_enabled", true),
		"localAuthenticationDisabled":    boolFrom(after, "local_authentication_disabled", false),
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.OperationalInsights/workspaces"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.OperationalInsights/workspaces",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
		SKU:           stringFrom(after, "sku"),
	}
}

// translateApplicationGateway — Microsoft.Network/applicationGateways.
// Rules examine WAF mode, TLS policy, and diagnostic logs.
func translateApplicationGateway(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	wafCfg := firstMap(after, "waf_configuration")
	sslPolicy := firstMap(after, "ssl_policy")
	props := map[string]interface{}{
		"webApplicationFirewallConfiguration": map[string]interface{}{
			"enabled":                 boolFrom(wafCfg, "enabled", false),
			"firewallMode":            stringFrom(wafCfg, "firewall_mode"),
			"ruleSetType":             stringFrom(wafCfg, "rule_set_type"),
			"ruleSetVersion":          stringFrom(wafCfg, "rule_set_version"),
		},
		"sslPolicy": map[string]interface{}{
			"policyType":          stringFrom(sslPolicy, "policy_type"),
			"minProtocolVersion":  stringFrom(sslPolicy, "min_protocol_version"),
		},
		"enableHttp2": boolFrom(after, "enable_http2", false),
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.Network/applicationGateways"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.Network/applicationGateways",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
	}
}

// translateFrontDoor — Microsoft.Network/frontDoors (also covers
// azurerm_cdn_frontdoor_profile, which the newer AzureRM provider
// treats as the canonical resource).
func translateFrontDoor(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	props := map[string]interface{}{
		"enabledState":      stringFrom(after, "enabled_state"),
		"friendlyName":      stringFrom(after, "friendly_name"),
		"responseTimeoutSeconds": intFrom(after, "response_timeout_seconds", 60),
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.Network/frontDoors"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.Network/frontDoors",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
	}
}

// translateAzureFirewall — Microsoft.Network/azureFirewalls. The SKU
// tier distinguishes Basic from Standard/Premium, and threat-intel
// mode is a posture signal.
func translateAzureFirewall(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	props := map[string]interface{}{
		"threatIntelMode":      stringFrom(after, "threat_intel_mode"),
		"dnsProxyEnabled":      boolFrom(after, "dns_proxy_enabled", false),
		"skuName":              stringFrom(after, "sku_name"),
		"skuTier":              stringFrom(after, "sku_tier"),
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.Network/azureFirewalls"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.Network/azureFirewalls",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
		SKU:           stringFrom(after, "sku_tier"),
	}
}

// translateBastionHost — Microsoft.Network/bastionHosts.
func translateBastionHost(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	props := map[string]interface{}{
		"sku":                     stringFrom(after, "sku"),
		"copyPasteEnabled":        boolFrom(after, "copy_paste_enabled", true),
		"fileCopyEnabled":         boolFrom(after, "file_copy_enabled", false),
		"ipConnectEnabled":        boolFrom(after, "ip_connect_enabled", false),
		"shareableLinkEnabled":    boolFrom(after, "shareable_link_enabled", false),
		"tunnelingEnabled":        boolFrom(after, "tunneling_enabled", false),
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.Network/bastionHosts"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.Network/bastionHosts",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
		SKU:           stringFrom(after, "sku"),
	}
}

// translateCognitiveAccount — Microsoft.CognitiveServices/accounts.
// Signals: network ACLs, local auth, managed identity, and custom
// subdomain (required for managed-identity auth).
func translateCognitiveAccount(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	netAcls := firstMap(after, "network_acls")
	props := map[string]interface{}{
		"publicNetworkAccess":       enabledDisabled(boolFrom(after, "public_network_access_enabled", true)),
		"customSubDomainName":       stringFrom(after, "custom_subdomain_name"),
		"disableLocalAuth":          boolFrom(after, "local_auth_enabled", true) == false,
		"networkAcls": map[string]interface{}{
			"defaultAction": stringFrom(netAcls, "default_action"),
		},
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.CognitiveServices/accounts"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.CognitiveServices/accounts",
		Kind:          stringFrom(after, "kind"),
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
		SKU:           stringFrom(after, "sku_name"),
	}
}

// translateManagedDisk — Microsoft.Compute/disks. Rules look at
// encryption-at-rest configuration and public network access.
func translateManagedDisk(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	props := map[string]interface{}{
		"diskEncryptionSetId":       stringFrom(after, "disk_encryption_set_id"),
		"encryption": map[string]interface{}{
			"type": stringFrom(after, "encryption_settings.0.type"),
		},
		"publicNetworkAccess":       enabledDisabled(boolFrom(after, "public_network_access_enabled", true)),
		"networkAccessPolicy":       stringFrom(after, "network_access_policy"),
		"osType":                    stringFrom(after, "os_type"),
		"diskSizeGB":                intFrom(after, "disk_size_gb", 0),
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.Compute/disks"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.Compute/disks",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
		SKU:           stringFrom(after, "storage_account_type"),
	}
}

// translateRecoveryServicesVault — Microsoft.RecoveryServices/vaults.
// Signals: soft delete, cross-region restore, immutability.
func translateRecoveryServicesVault(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	props := map[string]interface{}{
		"softDeleteEnabled":          boolFrom(after, "soft_delete_enabled", true),
		"crossRegionRestoreEnabled":  boolFrom(after, "cross_region_restore_enabled", false),
		"publicNetworkAccessEnabled": enabledDisabled(boolFrom(after, "public_network_access_enabled", true)),
		"immutability":               stringFrom(after, "immutability"),
		"storageModeType":            stringFrom(after, "storage_mode_type"),
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.RecoveryServices/vaults"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.RecoveryServices/vaults",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
		SKU:           stringFrom(after, "sku"),
	}
}

// translateNetworkWatcher — Microsoft.Network/networkWatchers. Rules
// check that network watcher is present per-region (CIS 6.x).
func translateNetworkWatcher(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	props := map[string]interface{}{}
	for k, v := range after {
		props[k] = v
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.Network/networkWatchers"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.Network/networkWatchers",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
	}
}

// translateVirtualNetworkGateway — Microsoft.Network/virtualNetworkGateways.
// Rules track SKU tier (Basic is end-of-life) and active-active mode.
func translateVirtualNetworkGateway(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	props := map[string]interface{}{
		"gatewayType":      stringFrom(after, "type"),
		"vpnType":          stringFrom(after, "vpn_type"),
		"activeActive":     boolFrom(after, "active_active", false),
		"enableBgp":        boolFrom(after, "enable_bgp", false),
		"generation":       stringFrom(after, "generation"),
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.Network/virtualNetworkGateways"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.Network/virtualNetworkGateways",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
		SKU:           stringFrom(after, "sku"),
	}
}

// translateContainerApp — Microsoft.App/containerApps. ARGUS rules for
// container apps are future-work; carrying the type through the IaC
// scanner today means future rules auto-pick up without a translator
// change. Ingress, registries, and identity are the signal-rich fields.
func translateContainerApp(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	ingress := firstMap(after, "ingress")
	identity := firstMap(after, "identity")
	props := map[string]interface{}{
		"configuration": map[string]interface{}{
			"ingress": map[string]interface{}{
				"external":           boolFrom(ingress, "external_enabled", false),
				"allowInsecure":      boolFrom(ingress, "allow_insecure_connections", false),
				"targetPort":         intFrom(ingress, "target_port", 0),
				"transport":          stringFrom(ingress, "transport"),
			},
		},
		"identity": map[string]interface{}{
			"type": stringFrom(identity, "type"),
		},
		"workloadProfileName": stringFrom(after, "workload_profile_name"),
		"revisionMode":        stringFrom(after, "revision_mode"),
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.App/containerApps"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.App/containerApps",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
	}
}

// translateSearchService — Microsoft.Search/searchServices. Signals:
// local auth, public network, and replica/partition sizing.
func translateSearchService(rc ResourceChange) models.AzureResource {
	after := rc.Change.After
	props := map[string]interface{}{
		"publicNetworkAccess":    enabledDisabled(boolFrom(after, "public_network_access_enabled", true)),
		"localAuthenticationEnabled": boolFrom(after, "local_authentication_enabled", true),
		"authenticationFailureMode":  stringFrom(after, "authentication_failure_mode"),
		"replicaCount":           intFrom(after, "replica_count", 1),
		"partitionCount":         intFrom(after, "partition_count", 1),
		"hostingMode":            stringFrom(after, "hosting_mode"),
	}
	for k, v := range after {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}
	return models.AzureResource{
		ID:            synthesizeID(rc, "Microsoft.Search/searchServices"),
		Name:          stringFrom(after, "name"),
		Type:          "Microsoft.Search/searchServices",
		Location:      stringFrom(after, "location"),
		ResourceGroup: stringFrom(after, "resource_group_name"),
		Properties:    props,
		Tags:          stringMapFrom(after, "tags"),
		SKU:           stringFrom(after, "sku"),
	}
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

func synthesizeID(rc ResourceChange, armType string) string {
	// Terraform plans don't include the eventual Azure resource ID (it's
	// only known post-apply). We synthesize a stable one from the plan
	// address so deduplication and evidence output work correctly.
	return fmt.Sprintf("/subscriptions/00000000-0000-0000-0000-000000000000/providers/%s/%s", armType, rc.Address)
}

func stringFrom(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func boolFrom(m map[string]interface{}, key string, def bool) bool {
	if m == nil {
		return def
	}
	v, ok := m[key]
	if !ok || v == nil {
		return def
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	}
	return def
}

func intFrom(m map[string]interface{}, key string, def int) int {
	if m == nil {
		return def
	}
	v, ok := m[key]
	if !ok || v == nil {
		return def
	}
	switch t := v.(type) {
	case int:
		return t
	case float64:
		return int(t)
	}
	// json.Number path
	if n, ok := v.(interface{ Int64() (int64, error) }); ok {
		if i, err := n.Int64(); err == nil {
			return int(i)
		}
	}
	return def
}

func stringSliceFrom(m map[string]interface{}, key string) []string {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, it := range arr {
		if s, ok := it.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func stringMapFrom(m map[string]interface{}, key string) map[string]string {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	obj, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	out := make(map[string]string, len(obj))
	for k, val := range obj {
		if s, ok := val.(string); ok {
			out[k] = s
		}
	}
	return out
}

// firstMap unwraps the first element of a Terraform `block` attribute.
// Terraform plan JSON represents nested blocks as arrays even when the
// schema is MaxItems=1, so most property accesses need this helper.
func firstMap(m map[string]interface{}, key string) map[string]interface{} {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	if direct, ok := v.(map[string]interface{}); ok {
		return direct
	}
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	if first, ok := arr[0].(map[string]interface{}); ok {
		return first
	}
	return nil
}

func sliceOfMapsFrom(m map[string]interface{}, key string) []map[string]interface{} {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]map[string]interface{}, 0, len(arr))
	for _, it := range arr {
		if obj, ok := it.(map[string]interface{}); ok {
			out = append(out, obj)
		}
	}
	return out
}

func firstString(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	return ss[0]
}

func toInterfaceSlice(ss []string) []interface{} {
	out := make([]interface{}, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func enabledDisabled(b bool) string {
	if b {
		return "Enabled"
	}
	return "Disabled"
}

func aadProfileFrom(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	return map[string]interface{}{
		"managed":                boolFrom(m, "managed", false),
		"enableAzureRBAC":        boolFrom(m, "azure_rbac_enabled", false),
		"adminGroupObjectIDs":    stringSliceFrom(m, "admin_group_object_ids"),
	}
}
