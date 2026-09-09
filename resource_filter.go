package easyconnect

import (
	"net/netip"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
)

// resourceFilter answers whether the gateway published a destination. Sending a
// datagram it did not publish makes the gateway flag the session and, after a
// second one, drop the tunnel, so outbound traffic is filtered here rather than
// left to the gateway.
type resourceFilter struct {
	singleAddresses map[netip.Addr][]PortRange
	prefixes        []filteredPrefix
}

type filteredPrefix struct {
	prefix netip.Prefix
	ports  PortRange
}

func newResourceFilter(resources []Resource, alwaysAllowed []netip.Addr) *resourceFilter {
	filter := &resourceFilter{singleAddresses: make(map[netip.Addr][]PortRange)}
	for _, resource := range resources {
		for _, entry := range resource.Entries {
			for _, prefix := range entry.Prefixes {
				filter.add(prefix, entry.Ports)
			}
		}
	}
	wholeRange := wholePortRange.Value()
	for _, address := range alwaysAllowed {
		filter.add(netip.PrefixFrom(address, address.BitLen()), wholeRange)
	}
	return filter
}

func (f *resourceFilter) add(prefix netip.Prefix, ports PortRange) {
	if prefix.IsSingleIP() {
		address := prefix.Addr()
		f.singleAddresses[address] = append(f.singleAddresses[address], ports)
		return
	}
	f.prefixes = append(f.prefixes, filteredPrefix{prefix: prefix.Masked(), ports: ports})
}

func (f *resourceFilter) permits(packet []byte) bool {
	destination, port, loaded := datagramDestination(packet)
	if !loaded {
		return false
	}
	if common.Any(f.singleAddresses[destination], func(it PortRange) bool {
		return port == 0 || it.Contains(port)
	}) {
		return true
	}
	if common.Any(f.prefixes, func(it filteredPrefix) bool {
		return it.prefix.Contains(destination) && (port == 0 || it.ports.Contains(port))
	}) {
		return true
	}
	return false
}

func datagramDestination(packet []byte) (netip.Addr, uint16, bool) {
	ipHeader := header.IPv4(packet)
	if !ipHeader.IsValid(len(packet)) {
		return netip.Addr{}, 0, false
	}
	destination := ipHeader.DestinationAddr()
	payload := ipHeader.Payload()
	var (
		transport   header.Transport
		minimumSize int
	)
	switch ipHeader.TransportProtocol() {
	case header.TCPProtocolNumber:
		transport, minimumSize = header.TCP(payload), header.TCPMinimumSize
	case header.UDPProtocolNumber:
		transport, minimumSize = header.UDP(payload), header.UDPMinimumSize
	default:
		// Every other protocol is filtered by address alone.
		return destination, 0, true
	}
	if len(payload) < minimumSize {
		return netip.Addr{}, 0, false
	}
	return destination, transport.DestinationPort(), true
}
