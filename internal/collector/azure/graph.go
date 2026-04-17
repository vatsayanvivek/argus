package azure

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"

	"github.com/vatsayanvivek/argus/internal/models"
)

// PrimaryKQL returns every resource in the subscription with enough metadata
// to feed downstream policy evaluation. The property bag is kept verbatim so
// OPA rules can reach into any nested field.
const PrimaryKQL = `resources
| project id, name, type, location, resourceGroup, subscriptionId, properties, tags, kind, sku
| order by type asc`

// NetworkKQL fetches only the network-plane resources that participate in
// chain correlation (NSGs, VNets, public IPs, application gateways, Azure
// Firewalls). We parse the property bag here rather than in OPA because the
// shape is highly nested.
const NetworkKQL = `resources
| where type in (
    'microsoft.network/networksecuritygroups',
    'microsoft.network/virtualnetworks',
    'microsoft.network/publicipaddresses',
    'microsoft.network/applicationgateways',
    'microsoft.network/azurefirewalls'
  )
| project id, name, type, properties, resourceGroup`

// collectResources runs the two Resource Graph queries and returns the flat
// resource list plus the parsed NetworkSnapshot. Any error from the SDK is
// soft-failed — we return whatever we managed to parse and the caller records
// the failure on the snapshot.
func collectResources(
	ctx context.Context,
	cred azcore.TokenCredential,
	subscriptionID string,
) ([]models.AzureResource, models.NetworkSnapshot, error) {
	resources := []models.AzureResource{}
	network := models.NetworkSnapshot{
		VNets:     []models.VirtualNetwork{},
		Subnets:   []models.Subnet{},
		NSGs:      []models.NetworkSecurityGroup{},
		PublicIPs: []models.PublicIP{},
		Peerings:  []models.VNetPeering{},
	}

	client, err := armresourcegraph.NewClient(cred, nil)
	if err != nil {
		return resources, network, fmt.Errorf("resource graph client: %w", err)
	}

	// -- Primary query: all resources.
	primaryRows, err := runGraphQuery(ctx, client, PrimaryKQL, subscriptionID)
	if err != nil {
		soft, code := classifyAzureError(err)
		if soft {
			log.Printf("[argus/azure] resource graph primary soft-failed (status=%d): %v", code, err)
		} else {
			return resources, network, fmt.Errorf("primary graph query: %w", err)
		}
	}
	for _, row := range primaryRows {
		r := parseResourceRow(row)
		if r.ID != "" {
			resources = append(resources, r)
		}
	}

	// -- Network query: nodes for topology graph.
	networkRows, err := runGraphQuery(ctx, client, NetworkKQL, subscriptionID)
	if err != nil {
		soft, code := classifyAzureError(err)
		if soft {
			log.Printf("[argus/azure] resource graph network soft-failed (status=%d): %v", code, err)
			return resources, network, nil
		}
		return resources, network, fmt.Errorf("network graph query: %w", err)
	}
	network = parseNetworkRows(networkRows)

	return resources, network, nil
}

// runGraphQuery executes a KQL query against Resource Graph and returns the
// rows as a slice of map[string]interface{}. Resource Graph returns the `Data`
// field as an `interface{}` which is usually a []interface{} of maps; the
// helper normalizes both the slice-of-maps and map-of-columns shapes.
func runGraphQuery(
	ctx context.Context,
	client *armresourcegraph.Client,
	query string,
	subscriptionID string,
) ([]map[string]interface{}, error) {
	rows := []map[string]interface{}{}

	subs := []*string{&subscriptionID}
	req := armresourcegraph.QueryRequest{
		Query:         toPtr(query),
		Subscriptions: subs,
	}

	resp, err := client.Resources(ctx, req, nil)
	if err != nil {
		return rows, err
	}
	if resp.Data == nil {
		return rows, nil
	}

	// Data is []interface{} (objectArray format) by default.
	if arr, ok := resp.Data.([]interface{}); ok {
		for _, item := range arr {
			if m, ok := item.(map[string]interface{}); ok {
				rows = append(rows, m)
			}
		}
		return rows, nil
	}

	// Fallback: table format {columns: [...], rows: [...]}
	if m, ok := resp.Data.(map[string]interface{}); ok {
		cols, _ := m["columns"].([]interface{})
		rawRows, _ := m["rows"].([]interface{})
		colNames := make([]string, 0, len(cols))
		for _, c := range cols {
			if cm, ok := c.(map[string]interface{}); ok {
				if name, ok := cm["name"].(string); ok {
					colNames = append(colNames, name)
				}
			}
		}
		for _, rr := range rawRows {
			if rarr, ok := rr.([]interface{}); ok {
				row := map[string]interface{}{}
				for i, v := range rarr {
					if i < len(colNames) {
						row[colNames[i]] = v
					}
				}
				rows = append(rows, row)
			}
		}
	}

	return rows, nil
}

// parseResourceRow converts one Resource Graph row into an AzureResource.
func parseResourceRow(row map[string]interface{}) models.AzureResource {
	r := models.AzureResource{
		ID:            stringField(row, "id"),
		Name:          stringField(row, "name"),
		Type:          stringField(row, "type"),
		Location:      stringField(row, "location"),
		ResourceGroup: stringField(row, "resourceGroup"),
		Properties:    mapField(row, "properties"),
		Tags:          stringMapField(row, "tags"),
		Kind:          stringField(row, "kind"),
	}
	// SKU can be a string or an object with a `name` field.
	if sku, ok := row["sku"]; ok && sku != nil {
		switch v := sku.(type) {
		case string:
			r.SKU = v
		case map[string]interface{}:
			if name, ok := v["name"].(string); ok {
				r.SKU = name
			}
		}
	}
	if r.Properties == nil {
		r.Properties = map[string]interface{}{}
	}
	if r.Tags == nil {
		r.Tags = map[string]string{}
	}
	return r
}

// parseNetworkRows walks the network-plane query results and builds the
// NetworkSnapshot. It handles NSGs, VNets (plus nested subnets and peerings),
// and public IPs.
func parseNetworkRows(rows []map[string]interface{}) models.NetworkSnapshot {
	net := models.NetworkSnapshot{
		VNets:     []models.VirtualNetwork{},
		Subnets:   []models.Subnet{},
		NSGs:      []models.NetworkSecurityGroup{},
		PublicIPs: []models.PublicIP{},
		Peerings:  []models.VNetPeering{},
	}

	for _, row := range rows {
		id := stringField(row, "id")
		name := stringField(row, "name")
		rtype := strings.ToLower(stringField(row, "type"))
		rg := stringField(row, "resourceGroup")
		props := mapField(row, "properties")

		switch rtype {
		case "microsoft.network/virtualnetworks":
			vnet := models.VirtualNetwork{
				ID:            id,
				Name:          name,
				ResourceGroup: rg,
				AddressSpace:  []string{},
			}
			if as, ok := props["addressSpace"].(map[string]interface{}); ok {
				if prefixes, ok := as["addressPrefixes"].([]interface{}); ok {
					for _, p := range prefixes {
						if s, ok := p.(string); ok {
							vnet.AddressSpace = append(vnet.AddressSpace, s)
						}
					}
				}
			}
			if ddos, ok := props["enableDdosProtection"].(bool); ok {
				vnet.DDoSEnabled = ddos
			}
			net.VNets = append(net.VNets, vnet)

			// Subnets are embedded on the VNet.
			if subnets, ok := props["subnets"].([]interface{}); ok {
				for _, s := range subnets {
					sm, ok := s.(map[string]interface{})
					if !ok {
						continue
					}
					sub := models.Subnet{
						ID:     stringField(sm, "id"),
						Name:   stringField(sm, "name"),
						VNetID: id,
					}
					sp := mapField(sm, "properties")
					if cidr, ok := sp["addressPrefix"].(string); ok {
						sub.CIDR = cidr
					}
					if nsgRef, ok := sp["networkSecurityGroup"].(map[string]interface{}); ok {
						if nsgID, ok := nsgRef["id"].(string); ok && nsgID != "" {
							sub.NSGID = nsgID
							sub.HasNSG = true
						}
					}
					net.Subnets = append(net.Subnets, sub)
				}
			}

			// Peerings are also embedded.
			if peerings, ok := props["virtualNetworkPeerings"].([]interface{}); ok {
				for _, p := range peerings {
					pm, ok := p.(map[string]interface{})
					if !ok {
						continue
					}
					peer := models.VNetPeering{
						ID:         stringField(pm, "id"),
						Name:       stringField(pm, "name"),
						SourceVNet: id,
					}
					pp := mapField(pm, "properties")
					if rv, ok := pp["remoteVirtualNetwork"].(map[string]interface{}); ok {
						if rvID, ok := rv["id"].(string); ok {
							peer.RemoteVNet = rvID
						}
					}
					if state, ok := pp["peeringState"].(string); ok {
						peer.State = state
					}
					net.Peerings = append(net.Peerings, peer)
				}
			}

		case "microsoft.network/networksecuritygroups":
			nsg := models.NetworkSecurityGroup{
				ID:            id,
				Name:          name,
				ResourceGroup: rg,
				InboundRules:  []models.NSGRule{},
				OutboundRules: []models.NSGRule{},
			}
			if rules, ok := props["securityRules"].([]interface{}); ok {
				for _, ru := range rules {
					rule := parseNSGRule(ru)
					if rule.Direction == "Outbound" {
						nsg.OutboundRules = append(nsg.OutboundRules, rule)
					} else {
						nsg.InboundRules = append(nsg.InboundRules, rule)
					}
				}
			}
			if defaults, ok := props["defaultSecurityRules"].([]interface{}); ok {
				for _, ru := range defaults {
					rule := parseNSGRule(ru)
					if rule.Direction == "Outbound" {
						nsg.OutboundRules = append(nsg.OutboundRules, rule)
					} else {
						nsg.InboundRules = append(nsg.InboundRules, rule)
					}
				}
			}
			// Flow logs are exposed on a separate resource; the best signal
			// we have in the property bag is the `flowLogs` array.
			if fl, ok := props["flowLogs"].([]interface{}); ok && len(fl) > 0 {
				nsg.FlowLogsEnabled = true
			}
			net.NSGs = append(net.NSGs, nsg)

		case "microsoft.network/publicipaddresses":
			pip := models.PublicIP{
				ID:   id,
				Name: name,
			}
			if addr, ok := props["ipAddress"].(string); ok {
				pip.IPAddress = addr
			}
			if ipConf, ok := props["ipConfiguration"].(map[string]interface{}); ok {
				if confID, ok := ipConf["id"].(string); ok {
					pip.AssociatedTo = confID
				}
			}
			net.PublicIPs = append(net.PublicIPs, pip)
		}
	}

	return net
}

// parseNSGRule handles both the direct rule shape and the Resource Graph
// object shape where rule attributes live under `properties`.
func parseNSGRule(raw interface{}) models.NSGRule {
	rule := models.NSGRule{}
	rm, ok := raw.(map[string]interface{})
	if !ok {
		return rule
	}
	rule.Name = stringField(rm, "name")
	props := mapField(rm, "properties")
	if len(props) == 0 {
		// Flat shape (rare, but supported).
		props = rm
	}
	if v, ok := props["protocol"].(string); ok {
		rule.Protocol = v
	}
	if v, ok := props["direction"].(string); ok {
		rule.Direction = v
	}
	if v, ok := props["access"].(string); ok {
		rule.Access = v
	}
	switch p := props["priority"].(type) {
	case float64:
		rule.Priority = int(p)
	case int:
		rule.Priority = p
	case int64:
		rule.Priority = int(p)
	}
	// Source address prefix may be a string or a list.
	if v, ok := props["sourceAddressPrefix"].(string); ok && v != "" {
		rule.SourceAddressPrefix = v
	} else if arr, ok := props["sourceAddressPrefixes"].([]interface{}); ok && len(arr) > 0 {
		parts := make([]string, 0, len(arr))
		for _, a := range arr {
			if s, ok := a.(string); ok {
				parts = append(parts, s)
			}
		}
		rule.SourceAddressPrefix = strings.Join(parts, ",")
	}
	if v, ok := props["sourcePortRange"].(string); ok && v != "" {
		rule.SourcePortRange = v
	} else if arr, ok := props["sourcePortRanges"].([]interface{}); ok && len(arr) > 0 {
		parts := make([]string, 0, len(arr))
		for _, a := range arr {
			if s, ok := a.(string); ok {
				parts = append(parts, s)
			}
		}
		rule.SourcePortRange = strings.Join(parts, ",")
	}
	if v, ok := props["destinationAddressPrefix"].(string); ok && v != "" {
		rule.DestinationAddressPrefix = v
	} else if arr, ok := props["destinationAddressPrefixes"].([]interface{}); ok && len(arr) > 0 {
		parts := make([]string, 0, len(arr))
		for _, a := range arr {
			if s, ok := a.(string); ok {
				parts = append(parts, s)
			}
		}
		rule.DestinationAddressPrefix = strings.Join(parts, ",")
	}
	if v, ok := props["destinationPortRange"].(string); ok && v != "" {
		rule.DestinationPortRange = v
	} else if arr, ok := props["destinationPortRanges"].([]interface{}); ok && len(arr) > 0 {
		parts := make([]string, 0, len(arr))
		for _, a := range arr {
			if s, ok := a.(string); ok {
				parts = append(parts, s)
			}
		}
		rule.DestinationPortRange = strings.Join(parts, ",")
	}
	return rule
}

// ---- small shared helpers ---------------------------------------------------

func toPtr[T any](v T) *T { return &v }

func stringField(m map[string]interface{}, k string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func mapField(m map[string]interface{}, k string) map[string]interface{} {
	if m == nil {
		return map[string]interface{}{}
	}
	if v, ok := m[k].(map[string]interface{}); ok {
		return v
	}
	return map[string]interface{}{}
}

func stringMapField(m map[string]interface{}, k string) map[string]string {
	out := map[string]string{}
	if m == nil {
		return out
	}
	if v, ok := m[k].(map[string]interface{}); ok {
		for kk, vv := range v {
			if s, ok := vv.(string); ok {
				out[kk] = s
			}
		}
	}
	return out
}
