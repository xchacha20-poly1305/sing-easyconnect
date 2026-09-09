package easyconnect

import (
	std_bufio "bufio"
	"cmp"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
)

const receiveBufferSize = 16 * 1024

type tunnelSession struct {
	client        *Client
	keepalive     *keepaliveChannel
	command       net.Conn
	upload        net.Conn
	receive       net.Conn
	receiveReader *std_bufio.Reader
	encoding      payloadEncoding
	filter        *resourceFilter
	configuration TunnelConfiguration

	dataKeepalive *dataChannelKeepalive

	writeAccess         sync.Mutex
	writeDeadlineFailed sync.Once
	lastWriteTime       atomic.Int64
	lastInboundTime     atomic.Int64
	ready               atomic.Bool
	runContext          context.Context
	stopRunning         context.CancelFunc
	running             sync.WaitGroup
	done                chan error
	failOnce            sync.Once
	closeOnce           sync.Once
	closeErr            error
}

func (c *Client) connectTunnel(ctx context.Context, web *webSession) (*tunnelSession, error) {
	destination := c.serverDestination()
	if web.parameters.tunnelPort != 0 {
		destination.Port = web.parameters.tunnelPort
	}
	session := &tunnelSession{
		client: c,
		done:   make(chan error, 1),
	}
	keepaliveStart := c.created
	if !c.options.KeepAliveSequenceDisguiseDisabled {
		keepaliveStart = disguisedClientStart()
	}
	var err error
	defer func() {
		if err != nil {
			_ = session.closeChannels()
		}
	}()
	session.keepalive, err = dialKeepaliveChannel(
		ctx,
		c.options.Dialer,
		destination,
		web.parameters.session,
		keepaliveOptions{
			interval: c.options.KeepAliveInterval,
			timeout:  c.options.KeepAliveTimeout,
			sequence: keepaliveSequence{clientStart: keepaliveStart},
		},
		c.options.Logger,
	)
	if err != nil {
		return nil, E.Cause(err, "connect keepalive channel")
	}
	var commandReply aabbMessage
	session.command, commandReply, err = dialL3Channel(
		ctx,
		c.options.Dialer,
		destination,
		web.parameters.session,
		jjyyTypeCommand,
		^uint32(0),
	)
	if err != nil {
		return nil, E.Cause(err, "connect command channel")
	}
	assignedAddress := netip.AddrFrom4(commandReply.Address)
	if !assignedAddress.IsValid() || assignedAddress.IsUnspecified() {
		err = E.Extend(ErrSessionRejected, "gateway assigned no address")
		return nil, err
	}
	session.encoding, err = parsePayloadEncoding(commandReply.Encryption, commandReply.Compression)
	if err != nil {
		return nil, err
	}
	channelAddressValue := channelAddress(assignedAddress)
	session.upload, _, err = dialL3Channel(
		ctx,
		c.options.Dialer,
		destination,
		web.parameters.session,
		jjyyTypeUpload,
		channelAddressValue,
	)
	if err != nil {
		return nil, E.Cause(err, "connect upload channel")
	}
	session.receive, _, err = dialL3Channel(
		ctx,
		c.options.Dialer,
		destination,
		web.parameters.session,
		jjyyTypeReceive,
		channelAddressValue,
	)
	if err != nil {
		return nil, E.Cause(err, "connect receive channel")
	}
	session.receiveReader = std_bufio.NewReaderSize(session.receive, receiveBufferSize)
	session.configuration = buildTunnelConfiguration(web.parameters, web.resources, web.hosts, assignedAddress, c.tunnelMTU(web.parameters))
	if !c.options.ResourceFilterDisabled {
		session.filter = newResourceFilter(web.resources, web.parameters.dns)
	}
	session.dataKeepalive, err = newDataChannelKeepalive(ctx, c.options, session.configuration, assignedAddress, session.filter)
	if err != nil {
		return nil, err
	}
	c.options.Logger.DebugContext(ctx, "tunnel address ", assignedAddress,
		", gateway address ", netip.AddrFrom4(commandReply.LocalAddress),
		", encoding ", commandReply.Encryption, "/", commandReply.Compression,
		", gateway UDP port ", commandReply.UDPPort)
	return session, nil
}

func (c *Client) tunnelMTU(parameters tunnelParameters) uint32 {
	return cmp.Or(c.options.MTU, parameters.mtu, DefaultMTU)
}

func (s *tunnelSession) Start() error {
	s.runContext, s.stopRunning = context.WithCancel(s.client.options.Context)
	s.markWritten()
	s.markInbound()
	s.ready.Store(true)
	s.running.Go(s.runKeepalive)
	s.running.Go(s.runCommandChannel)
	s.running.Go(s.runReceiveChannel)
	if s.dataKeepalive != nil {
		s.running.Go(s.runDataChannelKeepalive)
	}
	return nil
}

func (s *tunnelSession) runDataChannelKeepalive() {
	s.Fail(E.Cause(s.dataKeepalive.run(s.runContext, s), "data channel keepalive"))
}

func (s *tunnelSession) markWritten() {
	s.lastWriteTime.Store(time.Now().UnixNano())
}

func (s *tunnelSession) lastWrite() time.Time {
	return time.Unix(0, s.lastWriteTime.Load())
}

func (s *tunnelSession) markInbound() {
	s.lastInboundTime.Store(time.Now().UnixNano())
}

func (s *tunnelSession) lastInbound() time.Time {
	return time.Unix(0, s.lastInboundTime.Load())
}

func (s *tunnelSession) runKeepalive() {
	err := s.keepalive.run(s.runContext)
	s.Fail(E.Cause(err, "keepalive channel"))
}

// runCommandChannel watches the command channel, which stays silent after the
// address assignment and only reports that the gateway dropped the session.
func (s *tunnelSession) runCommandChannel() {
	_, err := bufio.Copy(io.Discard, s.command)
	if err != nil {
		s.Fail(E.Cause(err, "command channel"))
		return
	}
}

func (s *tunnelSession) runReceiveChannel() {
	for {
		packetBuffer, err := readDataPacket(s.receiveReader, s.encoding)
		if err != nil {
			s.Fail(E.Cause(err, "receive channel"))
			return
		}
		s.markInbound()
		if s.dataKeepalive != nil && s.dataKeepalive.ownsEchoReply(packetBuffer.Bytes()) {
			packetBuffer.Release()
			continue
		}
		s.client.pushIncomingDataPacketContext(s.runContext, packetBuffer)
	}
}

func (s *tunnelSession) Done() <-chan error {
	return s.done
}

func (s *tunnelSession) Ready() bool {
	return s.ready.Load()
}

func (s *tunnelSession) TunnelConfiguration() TunnelConfiguration {
	return s.configuration
}

func (s *tunnelSession) WriteDataPackets(packets [][]byte) error {
	return s.WriteDataPacketBuffers(newPacketBuffersFrom(packets))
}

func (s *tunnelSession) WriteDataPacketBuffers(packetBuffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(packetBuffers)
	if !s.ready.Load() {
		return ErrDataChannelNotReady
	}
	frames := make(net.Buffers, 0, len(packetBuffers))
	for index, packetBuffer := range packetBuffers {
		if s.filter != nil && !s.filter.permits(packetBuffer.Bytes()) {
			// The gateway drops the tunnel over a datagram it did not publish.
			s.client.droppedOutgoingDataPackets.Add(1)
			continue
		}
		packetBuffers[index] = frameDataPacket(packetBuffer, s.encoding)
		frames = append(frames, packetBuffers[index].Bytes())
	}
	if len(frames) == 0 {
		return nil
	}
	s.writeAccess.Lock()
	defer s.writeAccess.Unlock()
	// The gateway watches the tunnel through the keepalive channel, so a data
	// connection the path stopped forwarding is reported by nothing but this
	// deadline; without it the write would hold until the kernel gives up
	// retransmitting, minutes later.
	deadlineErr := s.upload.SetWriteDeadline(time.Now().Add(s.client.options.DataChannelTimeout))
	if deadlineErr != nil {
		s.writeDeadlineFailed.Do(func() {
			s.client.options.Logger.Warn(E.Cause(deadlineErr, "upload channel takes no write deadline"))
		})
	}
	_, err := frames.WriteTo(s.upload)
	if err != nil {
		err = E.Cause(err, "upload channel")
		s.Fail(err)
		return err
	}
	s.markWritten()
	return nil
}

func (s *tunnelSession) Fail(err error) {
	s.failOnce.Do(func() {
		s.ready.Store(false)
		if err == nil {
			err = E.New("tunnel session ended")
		}
		s.done <- err
		close(s.done)
	})
}

func (s *tunnelSession) Close() error {
	s.closeOnce.Do(func() {
		s.ready.Store(false)
		s.Fail(ErrClientClosed)
		if s.stopRunning != nil {
			s.stopRunning()
		}
		s.closeErr = s.closeChannels()
		s.running.Wait()
	})
	return s.closeErr
}

func (s *tunnelSession) closeChannels() error {
	return common.Close(
		common.PtrOrNil(s.keepalive),
		s.command,
		s.upload,
		s.receive,
	)
}
