package easyconnect

import (
	"net/netip"
	"slices"
)

type TunnelConfigurationEventReason string

const (
	TunnelConfigurationEventInitial         TunnelConfigurationEventReason = "initial"
	TunnelConfigurationEventReestablishment TunnelConfigurationEventReason = "reestablishment"
)

type TunnelConfiguration struct {
	MTU           uint32
	Addresses     []netip.Prefix
	Routes        []TunnelRoute
	DNS           []netip.Addr
	Hosts         []DNSHost
	SearchDomains []string
	Resources     []Resource
}

// DNSHost is one name from rclist <Dns data="id:host:ipv4">. The official
// client serves this table from a local stub; iptunDns is often 0.0.0.0.
type DNSHost struct {
	Domain    string
	Addresses []netip.Addr
}

type TunnelRoute struct {
	Prefix netip.Prefix
}

type TunnelConfigurationEvent struct {
	Reason        TunnelConfigurationEventReason
	Configuration TunnelConfiguration
}

func cloneTunnelConfiguration(configuration TunnelConfiguration) TunnelConfiguration {
	configuration.Addresses = slices.Clone(configuration.Addresses)
	configuration.Routes = slices.Clone(configuration.Routes)
	configuration.DNS = slices.Clone(configuration.DNS)
	configuration.Hosts = cloneDNSHosts(configuration.Hosts)
	configuration.SearchDomains = slices.Clone(configuration.SearchDomains)
	configuration.Resources = cloneResources(configuration.Resources)
	return configuration
}

func cloneDNSHosts(hosts []DNSHost) []DNSHost {
	hosts = slices.Clone(hosts)
	for i := range hosts {
		hosts[i].Addresses = slices.Clone(hosts[i].Addresses)
	}
	return hosts
}

func buildTunnelConfiguration(
	parameters tunnelParameters,
	resources []Resource,
	hosts []DNSHost,
	assignedAddress netip.Addr,
	mtu uint32,
) TunnelConfiguration {
	configuration := TunnelConfiguration{
		MTU:       mtu,
		DNS:       slices.Clone(parameters.dns),
		Hosts:     cloneDNSHosts(hosts),
		Resources: resources,
	}
	if assignedAddress.IsValid() {
		configuration.Addresses = []netip.Prefix{netip.PrefixFrom(assignedAddress, assignedAddress.BitLen())}
	}
	routes := make([]netip.Prefix, 0, len(resources))
	for _, resource := range resources {
		routes = append(routes, resource.Prefixes()...)
		configuration.SearchDomains = append(configuration.SearchDomains, resource.Domains()...)
	}
	for _, host := range hosts {
		configuration.SearchDomains = append(configuration.SearchDomains, host.Domain)
		for _, address := range host.Addresses {
			routes = append(routes, netip.PrefixFrom(address, address.BitLen()))
		}
	}
	for _, address := range parameters.dns {
		routes = append(routes, netip.PrefixFrom(address, address.BitLen()))
	}
	for _, prefix := range mergePrefixes(routes) {
		configuration.Routes = append(configuration.Routes, TunnelRoute{Prefix: prefix})
	}
	configuration.SearchDomains = sortedUnique(configuration.SearchDomains)
	return configuration
}

func mergePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	prefixes = slices.Clone(prefixes)
	slices.SortFunc(prefixes, func(a netip.Prefix, b netip.Prefix) int {
		if compared := a.Addr().Compare(b.Addr()); compared != 0 {
			return compared
		}
		return a.Bits() - b.Bits()
	})
	merged := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			continue
		}
		prefix = prefix.Masked()
		if len(merged) > 0 && merged[len(merged)-1].Overlaps(prefix) && merged[len(merged)-1].Bits() <= prefix.Bits() {
			continue
		}
		merged = append(merged, prefix)
	}
	return merged
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	values = slices.Clone(values)
	slices.Sort(values)
	return slices.Compact(values)
}
