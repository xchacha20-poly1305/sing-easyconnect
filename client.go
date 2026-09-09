package easyconnect

import (
	"cmp"
	"context"
	"math"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	DefaultMTU = 1400

	defaultKeepAliveInterval       = time.Second // from official
	defaultKeepAliveTimeout        = 30 * time.Second
	defaultDataChannelTimeout      = 30 * time.Second
	defaultReconnectTimeout        = 300 * time.Second
	defaultDataPacketQueueCapacity = 32
	minimumConfiguredMTU           = 576
)

type Client struct {
	options ClientOptions
	// created stands in for the launch of the reference client, which is one
	// VPN client per process.
	created       time.Time
	serverURL     *url.URL
	httpClient    *http.Client
	httpTransport *http.Transport

	configurationAccess       sync.RWMutex
	tunnelConfiguration       TunnelConfiguration
	configurationEventAccess  sync.Mutex
	configurationEvents       []TunnelConfigurationEvent
	configurationEventWake    chan struct{}
	configurationEventStopped bool

	droppedOutgoingDataPackets   atomic.Uint64
	incomingDataPackets          *dataPacketQueue[*buf.Buffer]
	outgoingDataPackets          *dataPacketQueue[outboundDataPacket]
	outgoingDataPacketWriterDone chan struct{}

	lifecycleAccess  sync.Mutex
	started          bool
	closed           bool
	suspended        atomic.Bool
	resumed          chan struct{}
	terminalError    error
	currentSession   clientSession
	publishedSession clientSession
	stateChanged     chan struct{}
	supervisorCancel context.CancelFunc
	supervisorDone   chan struct{}
	closeOnce        sync.Once
	closeErr         error
}

func NewClient(options ClientOptions) (*Client, error) {
	if options.Server == "" {
		return nil, ErrMissingServer
	}
	if options.Username == "" || options.Password == "" {
		return nil, ErrMissingCredentials
	}
	if options.Device == "" {
		return nil, ErrMissingDevice
	}
	options = options.Clone()
	options.Language = cmp.Or(options.Language, defaultLanguage)
	if options.KeepAliveInterval <= 0 {
		options.KeepAliveInterval = defaultKeepAliveInterval
	}
	if options.KeepAliveTimeout <= 0 {
		options.KeepAliveTimeout = defaultKeepAliveTimeout
	}
	if options.DataChannelTimeout <= 0 {
		options.DataChannelTimeout = defaultDataChannelTimeout
	}
	if options.DataChannelKeepAliveInterval < 0 {
		return nil, E.New("data channel keepalive interval cannot be negative")
	}
	if options.DataChannelKeepAliveTimeout < 0 {
		return nil, E.New("data channel keepalive timeout cannot be negative")
	}
	if options.DataChannelKeepAliveTimeout > 0 && options.DataChannelKeepAliveInterval == 0 {
		return nil, E.New("data channel keepalive timeout requires an interval")
	}
	options.ReconnectTimeout = cmp.Or(options.ReconnectTimeout, defaultReconnectTimeout)
	if options.ReconnectTimeout < 0 {
		return nil, E.New("reconnect timeout cannot be negative")
	}
	if options.MTU != 0 && options.MTU < minimumConfiguredMTU {
		options.MTU = minimumConfiguredMTU
	}
	options.QueueLength = cmp.Or(options.QueueLength, defaultDataPacketQueueCapacity)
	if uint64(options.QueueLength) > math.MaxInt {
		return nil, E.New("packet queue length exceeds platform limit")
	}
	serverURL, err := parseServerURL(options.Server)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := buildClientTLS(options)
	if err != nil {
		return nil, err
	}
	client := &Client{
		options:                options,
		created:                time.Now(),
		serverURL:              serverURL,
		configurationEventWake: make(chan struct{}, 1),
		incomingDataPackets:    newDataPacketQueue[*buf.Buffer](int(options.QueueLength)),
		outgoingDataPackets:    newDataPacketQueue[outboundDataPacket](int(options.QueueLength)),
		stateChanged:           make(chan struct{}),
	}
	client.httpClient, client.httpTransport, err = newHTTPClient(client, tlsConfig)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (c *Client) Start() error {
	c.lifecycleAccess.Lock()
	if c.started {
		c.lifecycleAccess.Unlock()
		return nil
	}
	if c.closed {
		c.lifecycleAccess.Unlock()
		return ErrClientClosed
	}
	supervisorContext, cancelSupervisor := context.WithCancel(c.options.Context)
	c.supervisorCancel = cancelSupervisor
	c.supervisorDone = make(chan struct{})
	c.outgoingDataPacketWriterDone = make(chan struct{})
	c.started = true
	c.lifecycleAccess.Unlock()
	if c.options.OnTunnelConfiguration != nil {
		go c.runTunnelConfigurationDispatcher()
	}
	go c.runOutgoingDataPacketWriter()
	go c.runSupervisor(supervisorContext)
	return nil
}

// RestartSession drops the established tunnel and authenticates again.
func (c *Client) RestartSession() {
	c.lifecycleAccess.Lock()
	session := c.currentSession
	c.lifecycleAccess.Unlock()
	c.httpTransport.CloseIdleConnections()
	if session != nil {
		session.Fail(E.New("session restart requested"))
	}
}

func (c *Client) Suspend() {
	c.lifecycleAccess.Lock()
	if c.suspended.Load() || c.closed {
		c.lifecycleAccess.Unlock()
		return
	}
	c.suspended.Store(true)
	c.resumed = make(chan struct{})
	session := c.publishedSession
	c.lifecycleAccess.Unlock()
	c.httpTransport.CloseIdleConnections()
	if session != nil {
		session.Fail(ErrClientSuspended)
	}
}

func (c *Client) Resume() {
	if !c.suspended.Load() {
		return
	}
	c.lifecycleAccess.Lock()
	if !c.suspended.Load() {
		c.lifecycleAccess.Unlock()
		return
	}
	c.suspended.Store(false)
	close(c.resumed)
	c.lifecycleAccess.Unlock()
}

func (c *Client) WaitReady(ctx context.Context) error {
	for {
		c.lifecycleAccess.Lock()
		stateChanged := c.stateChanged
		terminalError := c.terminalError
		closed := c.closed
		ready := c.currentSession != nil && c.publishedSession == c.currentSession && c.currentSession.Ready()
		c.lifecycleAccess.Unlock()
		if terminalError != nil {
			return terminalError
		}
		if closed {
			return ErrClientClosed
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-stateChanged:
		}
	}
}

func (c *Client) Ready() bool {
	return c.readySession() != nil
}

func (c *Client) ReadDataPacket(ctx context.Context) ([]byte, error) {
	packetBuffer, err := c.ReadDataPacketBuffer(ctx)
	if err != nil {
		return nil, err
	}
	payload := slices.Clone(packetBuffer.Bytes())
	packetBuffer.Release()
	return payload, nil
}

func (c *Client) ReadDataPackets(ctx context.Context) ([]*buf.Buffer, error) {
	return c.readDataPackets(ctx, 0)
}

func (c *Client) ReadDataPacketBuffer(ctx context.Context) (*buf.Buffer, error) {
	packetBuffers, err := c.readDataPackets(ctx, 1)
	if err != nil {
		return nil, err
	}
	return packetBuffers[0], nil
}

func (c *Client) readDataPackets(ctx context.Context, maximumPackets int) ([]*buf.Buffer, error) {
	for {
		c.lifecycleAccess.Lock()
		stateChanged := c.stateChanged
		terminalError := c.terminalError
		closed := c.closed
		c.lifecycleAccess.Unlock()
		if terminalError != nil {
			return nil, terminalError
		}
		if closed {
			return nil, ErrClientClosed
		}
		packetBuffers := c.incomingDataPackets.Pop(maximumPackets)
		if len(packetBuffers) > 0 {
			return packetBuffers, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-stateChanged:
		case <-c.incomingDataPackets.Wake():
		}
	}
}

func (c *Client) WriteDataPacket(packet []byte) error {
	return c.WriteDataPackets([][]byte{packet})
}

func (c *Client) WriteDataPackets(packets [][]byte) error {
	if len(packets) == 0 {
		return nil
	}
	return c.WriteDataPacketBuffers(newPacketBuffersFrom(packets))
}

func (c *Client) WriteDataPacketBuffers(packetBuffers []*buf.Buffer) error {
	if len(packetBuffers) == 0 {
		return nil
	}
	session := c.readySession()
	if session == nil {
		buf.ReleaseMulti(packetBuffers)
		return ErrDataChannelNotReady
	}
	return c.enqueueOutboundDataPacketBuffers(session, packetBuffers)
}

func (c *Client) DroppedOutgoingDataPackets() uint64 {
	return c.droppedOutgoingDataPackets.Load()
}

func (c *Client) TunnelConfiguration() TunnelConfiguration {
	c.configurationAccess.RLock()
	defer c.configurationAccess.RUnlock()
	return cloneTunnelConfiguration(c.tunnelConfiguration)
}

func (c *Client) setTunnelConfiguration(configuration TunnelConfiguration) TunnelConfiguration {
	c.configurationAccess.Lock()
	c.tunnelConfiguration = configuration
	c.configurationAccess.Unlock()
	return configuration
}

func (c *Client) publishTunnelConfigurationEvent(reason TunnelConfigurationEventReason, configuration TunnelConfiguration) {
	if c.options.OnTunnelConfiguration == nil {
		return
	}
	c.configurationEventAccess.Lock()
	if !c.configurationEventStopped {
		c.configurationEvents = append(c.configurationEvents, TunnelConfigurationEvent{
			Reason:        reason,
			Configuration: cloneTunnelConfiguration(configuration),
		})
	}
	c.configurationEventAccess.Unlock()
	select {
	case c.configurationEventWake <- struct{}{}:
	default:
	}
}

func (c *Client) runTunnelConfigurationDispatcher() {
	for {
		c.configurationEventAccess.Lock()
		if c.configurationEventStopped {
			c.configurationEvents = nil
			c.configurationEventAccess.Unlock()
			return
		}
		if len(c.configurationEvents) == 0 {
			c.configurationEventAccess.Unlock()
			<-c.configurationEventWake
			continue
		}
		event := c.configurationEvents[0]
		c.configurationEvents[0] = TunnelConfigurationEvent{}
		c.configurationEvents = c.configurationEvents[1:]
		c.configurationEventAccess.Unlock()
		err := c.options.OnTunnelConfiguration(event)
		if err == nil {
			continue
		}
		failure := E.Errors(errTunnelConfiguration, E.Cause(err, "apply easyconnect tunnel configuration"))
		c.configurationEventAccess.Lock()
		c.configurationEventStopped = true
		c.configurationEvents = nil
		c.configurationEventAccess.Unlock()
		c.lifecycleAccess.Lock()
		session := c.currentSession
		c.lifecycleAccess.Unlock()
		c.setTerminalError(failure)
		if session != nil {
			session.Fail(failure)
		}
		return
	}
}

func (c *Client) pushIncomingDataPacketContext(ctx context.Context, packetBuffer *buf.Buffer) {
	if packetBuffer == nil {
		return
	}
	if packetBuffer.IsEmpty() {
		packetBuffer.Release()
		return
	}
	if c.incomingDataPackets.PushBatch(ctx, []*buf.Buffer{packetBuffer}) == 0 {
		packetBuffer.Release()
	}
}

func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.lifecycleAccess.Lock()
		c.closed = true
		if c.supervisorCancel != nil {
			c.supervisorCancel()
		}
		session := c.currentSession
		supervisorDone := c.supervisorDone
		outgoingDataPacketWriterDone := c.outgoingDataPacketWriterDone
		c.signalStateChangedLocked()
		c.lifecycleAccess.Unlock()
		c.incomingDataPackets.Close()
		c.outgoingDataPackets.Close()
		c.configurationEventAccess.Lock()
		c.configurationEventStopped = true
		c.configurationEvents = nil
		c.configurationEventAccess.Unlock()
		select {
		case c.configurationEventWake <- struct{}{}:
		default:
		}
		if session != nil {
			c.closeErr = E.Errors(c.closeErr, session.Close())
		}
		if supervisorDone != nil {
			<-supervisorDone
		}
		if outgoingDataPacketWriterDone != nil {
			<-outgoingDataPacketWriterDone
		}
		c.httpTransport.CloseIdleConnections()
		c.incomingDataPackets.Drain((*buf.Buffer).Release)
	})
	return c.closeErr
}
