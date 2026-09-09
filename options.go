package easyconnect

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/netip"
	"time"

	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

type ClientTLSOptions struct {
	Config               *tls.Config
	ServerName           string
	Insecure             bool
	SystemTrustDisabled  bool
	CertificateAuthority Material
}

type ClientOptions struct {
	Context  context.Context
	Server   string
	Username string
	Password string

	// Device marks the unique device, service may reject the request if empty.
	// Original implementation default to use the OS name in lowercase.
	Device string
	// Language can be empty. Default is hard-coded string "en_US".
	Language string

	// MTU overrides the tunnel MTU advertised by conf.csp.
	MTU uint32

	// QueueLength bounds the number of data packets buffered in each direction.
	QueueLength uint32

	KeepAliveInterval time.Duration
	KeepAliveTimeout  time.Duration

	// KeepAliveSequenceDisguiseDisabled numbers the keepalive messages with the
	// seconds since this Client was created, the way the reference client
	// numbers them with its own uptime. By default the counter is disguised: it
	// starts at a random point below an hour when the tunnel opens, so a client
	// held open for weeks does not announce that in a field the gateway only
	// echoes back.
	KeepAliveSequenceDisguiseDisabled bool

	// DataChannelTimeout bounds one write on the upload channel. The gateway
	// answers the keepalive channel from a different socket, so a path that
	// silently stopped forwarding the data channels — an evicted NAT entry, a
	// changed route — is noticed nowhere else, and an unbounded write would
	// hold the tunnel until the kernel gives up on retransmitting.
	DataChannelTimeout time.Duration

	// DataChannelKeepAliveInterval sends a probe datagram through the tunnel
	// once the upload channel has been idle for this long, so that the data
	// connections stay in the state tables the keepalive channel keeps its own
	// entry alive in. Zero, the default, sends nothing: the reference client
	// leaves its data channels silent, and so does this one.
	DataChannelKeepAliveInterval time.Duration

	// DataChannelKeepAliveDestination overrides the probe destination. It must
	// be an address the published resource list covers, since the gateway drops
	// the tunnel over a datagram it did not publish; one that is not covered
	// fails the tunnel. Unset, the probes go to the first address the gateway
	// itself named — a DNS server from conf.csp, an rclist host record, or a
	// single-address resource — and the probe stands down if it named none.
	DataChannelKeepAliveDestination netip.Addr

	// DataChannelKeepAliveTimeout drops the tunnel when the receive channel
	// stays silent for this long while probes are being sent. It is off by
	// default, and requires DataChannelKeepAliveInterval: the probe destination
	// answers the probes or it does not, and only the deployment knows which.
	DataChannelKeepAliveTimeout time.Duration

	ReconnectTimeout time.Duration

	// ResourceRoutesDisabled keeps the routes of the published resource list out
	// of the tunnel configuration, leaving only the assigned address prefix.
	ResourceRoutesDisabled bool

	// ResourceFilterDisabled stops the client from dropping outbound datagrams
	// that the published resource list does not cover. The gateway treats such
	// a datagram as a violation and drops the tunnel after a few of them.
	ResourceFilterDisabled bool

	TLSConfig             ClientTLSOptions
	Dialer                N.Dialer
	Logger                logger.ContextLogger
	OnTunnelConfiguration func(event TunnelConfigurationEvent) error
}

func (c ClientOptions) Clone() ClientOptions {
	c.TLSConfig.CertificateAuthority.Content = bytes.Clone(c.TLSConfig.CertificateAuthority.Content)
	if tlsConfig := c.TLSConfig.Config; tlsConfig != nil {
		c.TLSConfig.Config = tlsConfig.Clone()
	}
	return c
}
