package easyconnect

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	clientReconnectInitialBackoff = time.Second
	clientReconnectMaximumBackoff = 60 * time.Second
)

type clientSession interface {
	Start() error
	Done() <-chan error
	WriteDataPackets(packets [][]byte) error
	WriteDataPacketBuffers(packetBuffers []*buf.Buffer) error
	Fail(err error)
	Close() error
	Ready() bool
	TunnelConfiguration() TunnelConfiguration
}

func isTerminalError(err error) bool {
	if err == nil {
		return false
	}
	if terminal, isTerminal := E.Cast[*TerminalError](err); isTerminal && terminal.Terminal() {
		return true
	}
	if E.IsMulti(err,
		ErrMissingServer,
		ErrMissingCredentials,
		ErrAuthenticationFailed,
		ErrMaterialSourceConflict,
		ErrInvalidTLSMaterial,
		ErrProtocolNotSupported,
		errTunnelConfiguration,
	) {
		return true
	}
	if _, unknownAuthority := E.Cast[x509.UnknownAuthorityError](err); unknownAuthority {
		return true
	}
	if _, hostnameError := E.Cast[x509.HostnameError](err); hostnameError {
		return true
	}
	if _, certificateError := E.Cast[x509.CertificateInvalidError](err); certificateError {
		return true
	}
	return false
}

func (c *Client) runSupervisor(ctx context.Context) {
	defer close(c.supervisorDone)
	defer c.closeSupervisorState()
	var web *webSession
	defer func() {
		c.releaseWebSession(web)
	}()
	backoff := clientReconnectInitialBackoff
	established := false
	reconnecting := false
	var reconnectTimeoutRemaining time.Duration
	for {
		if ctx.Err() != nil || c.isClosed() {
			return
		}
		if !c.waitResumed(ctx) {
			return
		}
		if web == nil {
			authenticated, err := c.authenticate(ctx)
			if err != nil {
				if ctx.Err() != nil || c.isClosed() {
					return
				}
				if isTerminalError(err) {
					c.options.Logger.ErrorContext(ctx, "easyconnect authentication failed permanently: ", err)
					c.setTerminalError(err)
					return
				}
				c.options.Logger.DebugContext(ctx, "authentication failed; retrying in ", backoff, ": ", err)
				if !c.waitClientReconnectBackoff(ctx, backoff, reconnecting, &reconnectTimeoutRemaining) {
					return
				}
				backoff = nextClientReconnectBackoff(backoff)
				continue
			}
			web = authenticated
		}
		published := false
		session, err := c.connectTunnel(ctx, web)
		if err == nil {
			published, err = c.runSession(ctx, session, established)
		}
		if ctx.Err() != nil || c.isClosed() {
			return
		}
		if errors.Is(err, ErrClientSuspended) || c.isSuspended() {
			backoff = clientReconnectInitialBackoff
			continue
		}
		if isTerminalError(err) {
			c.options.Logger.ErrorContext(ctx, "easyconnect tunnel failed permanently: ", err)
			c.setTerminalError(err)
			return
		}
		// The gateway ties the tunnel to the authenticated session,
		// so a failed tunnel restarts from the web endpoints with a fresh one.
		c.releaseWebSession(web)
		web = nil
		if published {
			// An established tunnel is worth re-establishing at once,
			// bounded by the reconnect timeout rather than by the backoff.
			established = true
			reconnecting = true
			reconnectTimeoutRemaining = c.options.ReconnectTimeout
			backoff = clientReconnectInitialBackoff
			c.options.Logger.DebugContext(ctx, "tunnel ended; retrying immediately: ", err)
			continue
		}
		c.options.Logger.DebugContext(ctx, "tunnel connection failed; retrying in ", backoff, ": ", err)
		if !c.waitClientReconnectBackoff(ctx, backoff, reconnecting, &reconnectTimeoutRemaining) {
			return
		}
		backoff = nextClientReconnectBackoff(backoff)
	}
}

func (c *Client) runSession(ctx context.Context, session *tunnelSession, reestablishment bool) (bool, error) {
	if !c.setCurrentSession(ctx, session) {
		return false, E.Errors(session.Close(), ErrClientClosed)
	}
	err := session.Start()
	if err != nil {
		c.clearCurrentSession(session)
		return false, E.Errors(err, session.Close())
	}
	reason := TunnelConfigurationEventInitial
	if reestablishment {
		reason = TunnelConfigurationEventReestablishment
	}
	configuration := c.setTunnelConfiguration(session.TunnelConfiguration())
	if !c.publishCurrentSession(ctx, session) {
		c.clearCurrentSession(session)
		return false, E.Errors(session.Close(), ErrClientClosed)
	}
	c.publishTunnelConfigurationEvent(reason, configuration)
	if reason == TunnelConfigurationEventInitial {
		c.options.Logger.InfoContext(ctx, "easyconnect tunnel established")
	} else {
		c.options.Logger.InfoContext(ctx, "easyconnect tunnel re-established")
	}
	if c.isSuspended() {
		session.Fail(ErrClientSuspended)
	}
	var sessionErr error
	select {
	case <-ctx.Done():
	case doneErr, open := <-session.Done():
		if open {
			sessionErr = doneErr
		}
	}
	sessionErr = E.Errors(sessionErr, session.Close())
	c.clearCurrentSession(session)
	if sessionErr == nil {
		sessionErr = E.New("tunnel ended without an error")
	}
	return true, sessionErr
}

func (c *Client) waitClientReconnectBackoff(
	ctx context.Context,
	backoff time.Duration,
	reconnecting bool,
	reconnectTimeoutRemaining *time.Duration,
) bool {
	wait := backoff
	if reconnecting {
		if *reconnectTimeoutRemaining <= 0 {
			c.setTerminalError(ErrReconnectTimeout)
			return false
		}
		if *reconnectTimeoutRemaining < wait {
			wait = *reconnectTimeoutRemaining
		}
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		if reconnecting {
			*reconnectTimeoutRemaining -= wait
		}
		return true
	}
}

func nextClientReconnectBackoff(backoff time.Duration) time.Duration {
	next := backoff * 2
	if next > clientReconnectMaximumBackoff {
		return clientReconnectMaximumBackoff
	}
	return next
}

func (c *Client) setCurrentSession(ctx context.Context, session clientSession) bool {
	c.lifecycleAccess.Lock()
	defer c.lifecycleAccess.Unlock()
	if c.closed || ctx.Err() != nil {
		return false
	}
	c.currentSession = session
	c.publishedSession = nil
	c.signalStateChangedLocked()
	return true
}

func (c *Client) publishCurrentSession(ctx context.Context, session clientSession) bool {
	c.lifecycleAccess.Lock()
	defer c.lifecycleAccess.Unlock()
	if c.closed || c.terminalError != nil || ctx.Err() != nil || c.currentSession != session || !session.Ready() {
		return false
	}
	c.publishedSession = session
	c.signalStateChangedLocked()
	return true
}

func (c *Client) clearCurrentSession(session clientSession) {
	c.lifecycleAccess.Lock()
	if c.currentSession == session {
		c.currentSession = nil
		c.publishedSession = nil
	}
	c.signalStateChangedLocked()
	c.lifecycleAccess.Unlock()
}

func (c *Client) readySession() clientSession {
	c.lifecycleAccess.Lock()
	defer c.lifecycleAccess.Unlock()
	if c.closed || c.terminalError != nil || c.currentSession == nil || c.publishedSession != c.currentSession || !c.currentSession.Ready() {
		return nil
	}
	return c.currentSession
}

func (c *Client) setTerminalError(err error) {
	if err == nil {
		err = E.New("session terminated")
	}
	c.lifecycleAccess.Lock()
	if c.closed {
		c.lifecycleAccess.Unlock()
		return
	}
	if c.terminalError == nil {
		c.terminalError = err
		c.signalStateChangedLocked()
	}
	cancelSupervisor := c.supervisorCancel
	c.lifecycleAccess.Unlock()
	if cancelSupervisor != nil {
		cancelSupervisor()
	}
}

func (c *Client) isClosed() bool {
	c.lifecycleAccess.Lock()
	defer c.lifecycleAccess.Unlock()
	return c.closed
}

func (c *Client) isSuspended() bool {
	c.lifecycleAccess.Lock()
	defer c.lifecycleAccess.Unlock()
	return c.suspended.Load()
}

func (c *Client) waitResumed(ctx context.Context) bool {
	c.lifecycleAccess.Lock()
	if !c.suspended.Load() {
		c.lifecycleAccess.Unlock()
		return true
	}
	resumed := c.resumed
	c.lifecycleAccess.Unlock()
	select {
	case <-ctx.Done():
		return false
	case <-resumed:
		return true
	}
}

func (c *Client) signalStateChangedLocked() {
	close(c.stateChanged)
	c.stateChanged = make(chan struct{})
}

func (c *Client) closeSupervisorState() {
	c.lifecycleAccess.Lock()
	if !c.closed && c.terminalError == nil {
		c.closed = true
	}
	c.currentSession = nil
	c.publishedSession = nil
	c.signalStateChangedLocked()
	c.lifecycleAccess.Unlock()
}
