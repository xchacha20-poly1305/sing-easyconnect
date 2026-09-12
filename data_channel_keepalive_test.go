package easyconnect

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

var (
	testProbeSource      = netip.MustParseAddr("10.20.30.40")
	testProbeDestination = netip.MustParseAddr("10.9.9.9")
)

type probeTarget struct {
	access   sync.Mutex
	written  [][]byte
	write    time.Time
	inbound  time.Time
	writeErr error
}

func newProbeTarget() *probeTarget {
	return &probeTarget{inbound: time.Now()}
}

func (t *probeTarget) lastWrite() time.Time {
	t.access.Lock()
	defer t.access.Unlock()
	return t.write
}

func (t *probeTarget) lastInbound() time.Time {
	t.access.Lock()
	defer t.access.Unlock()
	return t.inbound
}

func (t *probeTarget) markInbound() {
	t.access.Lock()
	defer t.access.Unlock()
	t.inbound = time.Now()
}

func (t *probeTarget) probes() int {
	t.access.Lock()
	defer t.access.Unlock()
	return len(t.written)
}

func (t *probeTarget) WriteDataPacketBuffers(packetBuffers []*buf.Buffer) error {
	t.access.Lock()
	defer t.access.Unlock()
	for _, packetBuffer := range packetBuffers {
		t.written = append(t.written, append([]byte(nil), packetBuffer.Bytes()...))
		packetBuffer.Release()
	}
	t.write = time.Now()
	return t.writeErr
}

func newTestKeepalive(t *testing.T, interval time.Duration, timeout time.Duration) *dataChannelKeepalive {
	t.Helper()
	keepalive, err := newDataChannelKeepalive(t.Context(), ClientOptions{
		DataChannelKeepAliveInterval:    interval,
		DataChannelKeepAliveTimeout:     timeout,
		DataChannelKeepAliveDestination: testProbeDestination,
		Logger:                          logger.NOP(),
	}, TunnelConfiguration{}, testProbeSource, nil)
	require.NoError(t, err)
	return keepalive
}

func TestDataChannelKeepAliveIsOffByDefault(t *testing.T) {
	t.Parallel()
	keepalive, err := newDataChannelKeepalive(t.Context(), ClientOptions{Logger: logger.NOP()}, TunnelConfiguration{}, testProbeSource, nil)
	require.NoError(t, err)
	require.Nil(t, keepalive)
}

func TestDataChannelKeepAliveTakesTheGatewayDNS(t *testing.T) {
	t.Parallel()
	keepalive, err := newDataChannelKeepalive(
		t.Context(),
		ClientOptions{DataChannelKeepAliveInterval: time.Minute, Logger: logger.NOP()},
		TunnelConfiguration{DNS: []netip.Addr{netip.IPv4Unspecified(), testProbeDestination}},
		testProbeSource,
		newResourceFilter(nil, []netip.Addr{testProbeDestination}),
	)
	require.NoError(t, err)
	require.Equal(t, testProbeDestination, keepalive.destination)
}

func TestDataChannelKeepAliveRefusesAnUnpublishedDestination(t *testing.T) {
	t.Parallel()
	_, err := newDataChannelKeepalive(
		t.Context(),
		ClientOptions{
			DataChannelKeepAliveInterval:    time.Minute,
			DataChannelKeepAliveDestination: testProbeDestination,
			Logger:                          logger.NOP(),
		},
		TunnelConfiguration{},
		testProbeSource,
		newResourceFilter(nil, nil),
	)
	require.Error(t, err)
	require.True(t, isTerminalError(err))
}

// A gateway whose conf.csp names no resolver — dnsserver 0.0.0.0 is the common
// case — still carries the tunnel, so the probe falls back to what rclist
// published and, failing that, stands down instead of taking the client with it.
func TestDataChannelKeepAliveFallsBackToTheHostRecords(t *testing.T) {
	t.Parallel()
	keepalive, err := newDataChannelKeepalive(
		t.Context(),
		ClientOptions{DataChannelKeepAliveInterval: time.Minute, Logger: logger.NOP()},
		TunnelConfiguration{
			DNS:   []netip.Addr{netip.IPv4Unspecified()},
			Hosts: []DNSHost{{Domain: "intranet", Addresses: []netip.Addr{testProbeDestination}}},
		},
		testProbeSource,
		newResourceFilter(nil, []netip.Addr{testProbeDestination}),
	)
	require.NoError(t, err)
	require.Equal(t, testProbeDestination, keepalive.destination)
}

func TestDataChannelKeepAliveFallsBackToASingleAddressResource(t *testing.T) {
	t.Parallel()
	resources := []Resource{{Entries: []ResourceEntry{
		{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/16")}, Ports: wholePortRange},
		{Prefixes: []netip.Prefix{netip.PrefixFrom(testProbeDestination, testProbeDestination.BitLen())}, Ports: wholePortRange},
	}}}
	keepalive, err := newDataChannelKeepalive(
		t.Context(),
		ClientOptions{DataChannelKeepAliveInterval: time.Minute, Logger: logger.NOP()},
		TunnelConfiguration{Resources: resources},
		testProbeSource,
		newResourceFilter(resources, nil),
	)
	require.NoError(t, err)
	require.Equal(t, testProbeDestination, keepalive.destination)
}

func TestDataChannelKeepAliveStandsDownWithoutADestination(t *testing.T) {
	t.Parallel()
	keepalive, err := newDataChannelKeepalive(
		t.Context(),
		ClientOptions{DataChannelKeepAliveInterval: time.Minute, Logger: logger.NOP()},
		TunnelConfiguration{DNS: []netip.Addr{netip.IPv4Unspecified()}},
		testProbeSource,
		newResourceFilter(nil, nil),
	)
	require.NoError(t, err)
	require.Nil(t, keepalive)
}

func TestDataChannelKeepAliveProbesOnlyWhenIdle(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		const interval = 30 * time.Second
		keepalive := newTestKeepalive(t, interval, 0)
		target := newProbeTarget()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go keepalive.run(ctx, target)

		// A tunnel that just wrote keeps its own state entries warm.
		time.Sleep(interval - time.Second)
		synctest.Wait()
		require.Equal(t, 0, target.probes())

		time.Sleep(2 * time.Second)
		synctest.Wait()
		require.Equal(t, 1, target.probes())
		require.True(t, keepalive.ownsEchoReply(echoReplyFor(target.written[0])))

		// The probe itself counts as a write, so the next one is a full
		// interval away.
		time.Sleep(interval - 2*time.Second)
		synctest.Wait()
		require.Equal(t, 1, target.probes())
	})
}

func TestDataChannelKeepAliveDropsASilentReceiveChannel(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		const interval = 30 * time.Second
		keepalive := newTestKeepalive(t, interval, 90*time.Second)
		target := newProbeTarget()
		done := make(chan error, 1)
		go func() {
			done <- keepalive.run(t.Context(), target)
		}()

		for range 3 {
			time.Sleep(interval)
			synctest.Wait()
			target.markInbound()
		}
		require.Equal(t, 3, target.probes())
		require.Empty(t, done)

		time.Sleep(4 * interval)
		synctest.Wait()
		require.ErrorIs(t, <-done, ErrDataChannelTimeout)
	})
}

func TestEchoRequestIsWellFormed(t *testing.T) {
	t.Parallel()
	keepalive := newTestKeepalive(t, time.Minute, 0)
	packetBuffer := keepalive.buildProbe()
	defer packetBuffer.Release()
	packet := packetBuffer.Bytes()

	ipHeader := header.IPv4(packet)
	require.Len(t, packet, echoRequestLength)
	require.True(t, ipHeader.IsValid(len(packet)))
	require.True(t, ipHeader.IsChecksumValid())
	require.Equal(t, testProbeSource, ipHeader.SourceAddr())
	require.Equal(t, testProbeDestination, ipHeader.DestinationAddr())
	require.EqualValues(t, header.ICMPv4ProtocolNumber, ipHeader.Protocol())
	message := header.ICMPv4(ipHeader.Payload())
	require.Equal(t, header.ICMPv4Echo, message.Type())
	require.Equal(t, message.Checksum(), header.ICMPv4Checksum(message, 0))

	require.True(t, keepalive.ownsEchoReply(echoReplyFor(packet)))
	// Datagrams the caller above the tunnel is waiting for stay its own.
	require.False(t, keepalive.ownsEchoReply(packet))
	require.False(t, keepalive.ownsEchoReply(testDatagram(testProbeDestination, 17, 53)))

	foreign := echoReplyFor(packet)
	header.ICMPv4(header.IPv4(foreign).Payload()).SetIdent(^keepalive.identifier)
	require.False(t, keepalive.ownsEchoReply(foreign))
}

func echoReplyFor(request []byte) []byte {
	reply := header.IPv4(append([]byte(nil), request...))
	reply.SetSourceAddr(header.IPv4(request).DestinationAddr())
	reply.SetDestinationAddr(header.IPv4(request).SourceAddr())
	header.ICMPv4(reply.Payload()).SetType(header.ICMPv4EchoReply)
	return reply
}
