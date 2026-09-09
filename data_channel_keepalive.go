package easyconnect

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

type dataChannelKeepalive struct {
	source      netip.Addr
	destination netip.Addr
	interval    time.Duration
	timeout     time.Duration
	identifier  uint16
	sequence    uint16
}

func newDataChannelKeepalive(
	ctx context.Context,
	options ClientOptions,
	configuration TunnelConfiguration,
	source netip.Addr,
	filter *resourceFilter,
) (*dataChannelKeepalive, error) {
	if options.DataChannelKeepAliveInterval == 0 {
		return nil, nil
	}
	if !source.Is4() {
		return nil, markTerminal(E.New("no data channel keepalive source: the gateway assigned no address"))
	}
	keepalive := &dataChannelKeepalive{
		source:     source,
		interval:   options.DataChannelKeepAliveInterval,
		timeout:    options.DataChannelKeepAliveTimeout,
		identifier: uint16(rand.Uint64()),
	}
	if configured := options.DataChannelKeepAliveDestination; configured.IsValid() {
		if !keepalive.reaches(configured, filter) {
			return nil, markTerminal(E.New("data channel keepalive destination ", configured, " is not published by the gateway"))
		}
		keepalive.destination = configured
		return keepalive, nil
	}
	for _, candidate := range pickProbeDestinations(configuration) {
		if keepalive.reaches(candidate, filter) {
			keepalive.destination = candidate
			return keepalive, nil
		}
	}
	// A tunnel with nowhere to send the probe is still a working tunnel, and
	// the probe is an aid to an idle one rather than a part of the protocol,
	// so a gateway that published no reachable address costs the probe instead
	// of the connection.
	options.Logger.WarnContext(ctx, "data channel keepalive disabled: the gateway published no address to probe")
	return nil, nil
}

func pickProbeDestinations(configuration TunnelConfiguration) []netip.Addr {
	destinations := slices.Clone(configuration.DNS)
	for _, host := range configuration.Hosts {
		destinations = append(destinations, host.Addresses...)
	}
	for _, resource := range configuration.Resources {
		for _, prefix := range resource.Prefixes() {
			if prefix.IsSingleIP() {
				destinations = append(destinations, prefix.Addr())
			}
		}
	}
	return destinations
}

func (k *dataChannelKeepalive) reaches(destination netip.Addr, filter *resourceFilter) bool {
	if !destination.Is4() || destination.IsUnspecified() {
		return false
	}
	if filter == nil {
		return true
	}
	probe := buildEchoRequest(k.source, destination, k.identifier, k.sequence)
	defer probe.Release()
	return filter.permits(probe.Bytes())
}

type dataChannelProbeTarget interface {
	lastWrite() time.Time
	lastInbound() time.Time
	WriteDataPacketBuffers(packetBuffers []*buf.Buffer) error
}

func (k *dataChannelKeepalive) run(ctx context.Context, session dataChannelProbeTarget) error {
	timer := time.NewTimer(k.interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
		now := time.Now()
		// Probing an active tunnel would only add a datagram the reference
		// client never sends; the state tables are already being refreshed.
		if idle := now.Sub(session.lastWrite()); idle < k.interval {
			timer.Reset(k.interval - idle)
			continue
		}
		if k.timeout > 0 {
			if silence := now.Sub(session.lastInbound()); silence > k.timeout {
				return E.Extend(ErrDataChannelTimeout, "receive channel silent for ", silence.Round(time.Second))
			}
		}
		err := session.WriteDataPacketBuffers([]*buf.Buffer{k.buildProbe()})
		if err != nil {
			return err
		}
		timer.Reset(k.interval)
	}
}

func (k *dataChannelKeepalive) buildProbe() *buf.Buffer {
	k.sequence++
	return buildEchoRequest(k.source, k.destination, k.identifier, k.sequence)
}

func (k *dataChannelKeepalive) ownsEchoReply(packet []byte) bool {
	ipHeader := header.IPv4(packet)
	if !ipHeader.IsValid(len(packet)) || ipHeader.TransportProtocol() != header.ICMPv4ProtocolNumber {
		return false
	}
	message := header.ICMPv4(ipHeader.Payload())
	if len(message) < header.ICMPv4MinimumSize {
		return false
	}
	return message.Type() == header.ICMPv4EchoReply &&
		message.Ident() == k.identifier &&
		ipHeader.SourceAddr() == k.destination
}

const (
	echoRequestLength = header.IPv4MinimumSize + header.ICMPv4MinimumSize
	ipv4DefaultTTL    = 64
)

func buildEchoRequest(source netip.Addr, destination netip.Addr, identifier uint16, sequence uint16) *buf.Buffer {
	packetBuffer := newPacketBuffer(echoRequestLength)
	packet := header.IPv4(packetBuffer.Extend(echoRequestLength))
	packet.Encode(&header.IPv4Fields{
		TotalLength: echoRequestLength,
		ID:          sequence,
		TTL:         ipv4DefaultTTL,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     source,
		DstAddr:     destination,
	})
	packet.SetChecksum(^packet.CalculateChecksum())

	message := header.ICMPv4(packet.Payload())
	message.SetType(header.ICMPv4Echo)
	message.SetCode(header.ICMPv4UnusedCode)
	message.SetIdent(identifier)
	message.SetSequence(sequence)
	message.SetChecksum(header.ICMPv4Checksum(message, 0))
	return packetBuffer
}
