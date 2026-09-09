package easyconnect

import (
	"encoding/binary"
	"math"
	"math/bits"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unique"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/ranges"
)

// Resource is one entry of the published resource list. The gateway only
// carries traffic towards what it publishes: a datagram to anything else is a
// violation that costs the tunnel, so the resource list is both the source of
// the tunnel routes and the outbound filter.
type Resource struct {
	ID      string
	Name    string
	Entries []ResourceEntry
}

// ResourceEntry is one host of a resource together with the port range
// published for it.
type ResourceEntry struct {
	Domain   string
	Prefixes []netip.Prefix
	Ports    PortRange
}

type PortRange ranges.Range[uint16]

func (p PortRange) Contains(port uint16) bool {
	return port >= p.Start && port <= p.End
}

var wholePortRange = unique.Make(PortRange(ranges.New(uint16(1), math.MaxUint16)))

func (r Resource) Prefixes() []netip.Prefix {
	return common.FlatMap(r.Entries, func(it ResourceEntry) []netip.Prefix {
		return it.Prefixes
	})
}

func (r Resource) Domains() []string {
	var domains []string
	for _, entry := range r.Entries {
		if entry.Domain != "" {
			domains = append(domains, entry.Domain)
		}
	}
	return domains
}

func parseResourceList(document *xmlElement) []Resource {
	elements := document.elements("Rc")
	resources := make([]Resource, 0, len(elements))
	for _, element := range elements {
		resource := Resource{
			ID:   element.attribute("id"),
			Name: element.attribute("name"),
		}
		hosts := strings.Split(element.attribute("host"), ";")
		ports := strings.Split(element.attribute("port"), ";")
		for i, host := range hosts {
			host = strings.TrimSpace(host)
			if host == "" {
				continue
			}
			entry := ResourceEntry{Ports: parsePortRange(ports, i)}
			entry.Domain, entry.Prefixes = parseResourceHost(host)
			if entry.Domain == "" && len(entry.Prefixes) == 0 {
				continue
			}
			resource.Entries = append(resource.Entries, entry)
		}
		if len(resource.Entries) == 0 {
			continue
		}
		resources = append(resources, resource)
	}
	return resources
}

func parsePortRange(ports []string, index int) PortRange {
	wholeRange := wholePortRange.Value()
	if index >= len(ports) {
		return wholeRange
	}
	start, end, found := strings.Cut(strings.TrimSpace(ports[index]), "~")
	if !found {
		end = start
	}
	startPort, startErr := strconv.ParseUint(strings.TrimSpace(start), 10, 16)
	endPort, endErr := strconv.ParseUint(strings.TrimSpace(end), 10, 16)
	if startErr != nil || endErr != nil || startPort == 0 || endPort < startPort {
		return wholeRange
	}
	return PortRange(ranges.New(uint16(startPort), uint16(endPort)))
}

func parseResourceHost(host string) (string, []netip.Prefix) {
	if start, end, isRange := strings.Cut(host, "~"); isRange {
		startAddress, startErr := netip.ParseAddr(strings.TrimSpace(start))
		endAddress, endErr := netip.ParseAddr(strings.TrimSpace(end))
		if startErr != nil || endErr != nil {
			return "", nil
		}
		return "", addressRangePrefixes(startAddress.Unmap(), endAddress.Unmap())
	}
	host = trimHostDecoration(host)
	if host == "" {
		return "", nil
	}
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap()
		return "", []netip.Prefix{netip.PrefixFrom(address, address.BitLen())}
	}
	return host, nil
}

func trimHostDecoration(host string) string {
	host = strings.TrimSpace(host)
	if scheme := strings.Index(host, "://"); scheme >= 0 {
		host = host[scheme+3:]
	}
	if path := strings.IndexAny(host, "/?#"); path >= 0 {
		host = host[:path]
	}
	if trimmed, _, err := net.SplitHostPort(host); err == nil {
		host = trimmed
	} else if literal, bracketed := strings.CutPrefix(host, "["); bracketed {
		host, _ = strings.CutSuffix(literal, "]")
	}
	return strings.Trim(host, ".")
}

func addressRangePrefixes(start netip.Addr, end netip.Addr) []netip.Prefix {
	if !start.Is4() || !end.Is4() {
		return nil
	}
	startOctets := start.As4()
	endOctets := end.As4()
	first := binary.BigEndian.Uint32(startOctets[:])
	last := binary.BigEndian.Uint32(endOctets[:])
	if first > last {
		return nil
	}
	var prefixes []netip.Prefix
	for {
		// The largest block starting at first is bounded by its alignment and
		// by the remaining size of the range.
		alignment := 32
		if first != 0 {
			alignment = bits.TrailingZeros32(first)
		}
		count := uint64(last-first) + 1
		size := bits.Len64(count)
		if count < 1<<size {
			size--
		}
		bitLength := 32 - min(alignment, size)
		prefixes = append(prefixes, netip.PrefixFrom(uint32Address(first), bitLength))
		blockSize := uint32(1) << (32 - bitLength)
		if first+blockSize-1 >= last {
			return prefixes
		}
		first += blockSize
	}
}

func uint32Address(value uint32) netip.Addr {
	var address [4]byte
	binary.BigEndian.PutUint32(address[:], value)
	return netip.AddrFrom4(address)
}

type dnsHostRecord struct {
	resourceID string
	domain     string
	address    netip.Addr
}

func parseDNSHostRecords(document *xmlElement) []dnsHostRecord {
	element := document.element("Dns")
	if element == nil {
		return nil
	}
	var records []dnsHostRecord
	for entry := range strings.SplitSeq(element.attribute("data"), ";") {
		record, loaded := parseDNSHostRecord(entry)
		if loaded {
			records = append(records, record)
		}
	}
	return records
}

func parseDNSHostRecord(entry string) (dnsHostRecord, bool) {
	entry = strings.TrimSpace(entry)
	first := strings.IndexByte(entry, ':')
	last := strings.LastIndexByte(entry, ':')
	if first <= 0 || last <= first {
		return dnsHostRecord{}, false
	}
	address, err := netip.ParseAddr(strings.TrimSpace(entry[last+1:]))
	if err != nil || !address.IsValid() || address.IsUnspecified() {
		return dnsHostRecord{}, false
	}
	address = address.Unmap()
	if !address.Is4() {
		return dnsHostRecord{}, false
	}
	domain, prefixes := parseResourceHost(strings.TrimSpace(entry[first+1 : last]))
	domain = canonicalResourceDomain(domain)
	if domain == "" || len(prefixes) > 0 {
		return dnsHostRecord{}, false
	}
	return dnsHostRecord{
		resourceID: strings.TrimSpace(entry[:first]),
		domain:     domain,
		address:    address,
	}, true
}

func parseDNSServers(document *xmlElement) []netip.Addr {
	element := document.element("Dns")
	if element == nil {
		return nil
	}
	var servers []netip.Addr
	for field := range strings.FieldsFuncSeq(element.attribute("dnsserver"), func(r rune) bool {
		return r == ';' || r == ',' || r == ' '
	}) {
		address, err := netip.ParseAddr(strings.TrimSpace(field))
		if err != nil || !address.IsValid() || address.IsUnspecified() {
			continue
		}
		servers = append(servers, address.Unmap())
	}
	return mergeAddresses(nil, servers)
}

func mergeAddresses(dst, src []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]bool, len(dst)+len(src))
	for _, address := range dst {
		seen[address] = true
	}
	for _, address := range src {
		if !address.IsValid() || address.IsUnspecified() || seen[address] {
			continue
		}
		seen[address] = true
		dst = append(dst, address)
	}
	return dst
}

func collectDNSHosts(records []dnsHostRecord) []DNSHost {
	index := make(map[string]int)
	seen := make(map[string]map[netip.Addr]bool)
	var hosts []DNSHost
	for _, record := range records {
		if record.domain == "" {
			continue
		}
		i, loaded := index[record.domain]
		if !loaded {
			i = len(hosts)
			index[record.domain] = i
			hosts = append(hosts, DNSHost{Domain: record.domain})
			seen[record.domain] = make(map[netip.Addr]bool)
		}
		if seen[record.domain][record.address] {
			continue
		}
		seen[record.domain][record.address] = true
		hosts[i].Addresses = append(hosts[i].Addresses, record.address)
	}
	slices.SortFunc(hosts, func(a, b DNSHost) int {
		return strings.Compare(a.Domain, b.Domain)
	})
	for i := range hosts {
		slices.SortFunc(hosts[i].Addresses, netip.Addr.Compare)
	}
	return hosts
}

func applyDNSHosts(resources []Resource, records []dnsHostRecord) []Resource {
	if len(records) == 0 {
		return resources
	}
	resources = cloneResources(resources)
	byID := make(map[string]int, len(resources))
	for i, resource := range resources {
		if resource.ID != "" {
			byID[resource.ID] = i
		}
	}
	for _, record := range records {
		prefix := netip.PrefixFrom(record.address, record.address.BitLen())
		index, loaded := byID[record.resourceID]
		if !loaded {
			resources = append(resources, Resource{
				ID: record.resourceID,
				Entries: []ResourceEntry{{
					Domain:   record.domain,
					Prefixes: []netip.Prefix{prefix},
					Ports:    wholePortRange.Value(),
				}},
			})
			byID[record.resourceID] = len(resources) - 1
			continue
		}
		entries := resources[index].Entries
		matched := false
		for i, entry := range entries {
			if canonicalResourceDomain(entry.Domain) != record.domain {
				continue
			}
			if !slices.Contains(entry.Prefixes, prefix) {
				entries[i].Prefixes = append(slices.Clone(entry.Prefixes), prefix)
			}
			matched = true
		}
		if !matched {
			entries = append(entries, ResourceEntry{
				Domain:   record.domain,
				Prefixes: []netip.Prefix{prefix},
				Ports:    wholePortRange.Value(),
			})
		}
		resources[index].Entries = entries
	}
	return resources
}

func cloneResources(resources []Resource) []Resource {
	resources = slices.Clone(resources)
	for i := range resources {
		entries := slices.Clone(resources[i].Entries)
		for j := range entries {
			entries[j].Prefixes = slices.Clone(entries[j].Prefixes)
		}
		resources[i].Entries = entries
	}
	return resources
}

func canonicalResourceDomain(domain string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
}
