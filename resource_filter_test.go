package easyconnect

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip"
	"github.com/sagernet/sing-tun/gtcpip/header"

	"github.com/stretchr/testify/require"
)

func testDatagram(destination netip.Addr, protocol byte, port uint16) []byte {
	var (
		transport     func([]byte) header.Transport
		transportSize int
	)
	switch tcpip.TransportProtocolNumber(protocol) {
	case header.TCPProtocolNumber:
		transport, transportSize = func(b []byte) header.Transport { return header.TCP(b) }, header.TCPMinimumSize
	default:
		transport, transportSize = func(b []byte) header.Transport { return header.UDP(b) }, header.UDPMinimumSize
	}
	packet := header.IPv4(make([]byte, header.IPv4MinimumSize+transportSize))
	packet.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         ipv4DefaultTTL,
		Protocol:    protocol,
		SrcAddr:     testProbeSource,
		DstAddr:     destination,
	})
	packet.SetChecksum(^packet.CalculateChecksum())
	transport(packet.Payload()).SetDestinationPort(port)
	return packet
}

func TestResourceFilter(t *testing.T) {
	t.Parallel()
	filter := newResourceFilter([]Resource{
		{Entries: []ResourceEntry{
			{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.1.253.6/32")}, Ports: PortRange{Start: 4430, End: 4430}},
			{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.1.253.6/32")}, Ports: PortRange{Start: 80, End: 90}},
			{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24")}, Ports: PortRange{Start: 443, End: 443}},
			{Domain: "www.example.edu", Ports: PortRange{Start: 443, End: 443}},
		}},
	}, []netip.Addr{netip.MustParseAddr("10.9.9.9")})

	for _, testCase := range []struct {
		name      string
		packet    []byte
		permitted bool
	}{
		{"published port", testDatagram(netip.MustParseAddr("10.1.253.6"), 6, 4430), true},
		{"second published range", testDatagram(netip.MustParseAddr("10.1.253.6"), 6, 85), true},
		{"unpublished port", testDatagram(netip.MustParseAddr("10.1.253.6"), 6, 22), false},
		{"published address, no port", testDatagram(netip.MustParseAddr("10.1.253.6"), 1, 0), true},
		{"published prefix", testDatagram(netip.MustParseAddr("192.168.7.9"), 17, 443), true},
		{"outside the prefix", testDatagram(netip.MustParseAddr("192.168.8.9"), 17, 443), false},
		{"configured DNS server", testDatagram(netip.MustParseAddr("10.9.9.9"), 17, 53), true},
		{"unpublished address", testDatagram(netip.MustParseAddr("10.2.2.2"), 6, 443), false},
		{"truncated datagram", []byte{0x45, 0x00}, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, testCase.permitted, filter.permits(testCase.packet))
		})
	}
}
