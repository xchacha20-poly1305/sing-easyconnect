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

type reconnectState struct {
	backoff          time.Duration
	established      bool
	reconnecting     bool
	timeoutRemaining time.Duration
}

func newReconnectState() reconnectState {
	return reconnectState{backoff: clientReconnectInitialBackoff}
}

func (s *reconnectState) tunnelLost(reconnectTimeout time.Duration) {
	s.established = true
	s.reconnecting = true
	s.timeoutRemaining = reconnectTimeout
	s.backoff = clientReconnectInitialBackoff
}

func (s *reconnectState) attemptFailed() {
	s.backoff = min(s.backoff*2, clientReconnectMaximumBackoff)
}

type clientSession interface {
	Start() error
	Done() <-chan error
	EnqueueDataPacketBuffers(packetBuffers []*buf.Buffer) error
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
		errTunnelEvent,
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
	reconnect := newReconnectState()
	for {
		if ctx.Err() != nil || c.isClosed() {
			return
		}
		if c.isSuspended() {
			// Nothing keeps an authenticated session across a suspension: the
			// gateway reclaims a session whose tunnel stopped answering, and
			// may refuse a second login beside one it still counts as online.
			web = c.discardWebSession(web)
			if !c.waitResumed(ctx) {
				return
			}
			// Resuming starts a run of its own. The tunnel that follows is not
			// the continuation of one the network took away, so it is not
			// charged to the reconnect timeout.
			reconnect = newReconnectState()
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
				c.options.Logger.DebugContext(ctx, "authentication failed; retrying in ", reconnect.backoff, ": ", err)
				if !c.waitClientReconnectBackoff(ctx, &reconnect) {
					return
				}
				reconnect.attemptFailed()
				continue
			}
			web = authenticated
			if c.isSuspended() {
				// Suspended while authenticating. The session is handed back at
				// the top of the loop rather than spent on a tunnel that would
				// be failed as soon as it is published.
				continue
			}
		}
		published := false
		session, err := c.connectTunnel(ctx, web)
		if err == nil {
			published, err = c.runSession(ctx, session, reconnect.established)
		}
		if ctx.Err() != nil || c.isClosed() {
			return
		}
		if errors.Is(err, ErrClientSuspended) || c.isSuspended() {
			// A suspension takes the session with the tunnel, whether or not
			// the client has been resumed again in the meantime.
			web = c.discardWebSession(web)
			reconnect = newReconnectState()
			continue
		}
		if isTerminalError(err) {
			c.options.Logger.ErrorContext(ctx, "easyconnect tunnel failed permanently: ", err)
			c.setTerminalError(err)
			return
		}
		// The gateway ties the tunnel to the authenticated session,
		// so a failed tunnel restarts from the web endpoints with a fresh one.
		web = c.discardWebSession(web)
		if published {
			// An established tunnel is worth re-establishing at once,
			// bounded by the reconnect timeout rather than by the backoff.
			reconnect.tunnelLost(c.options.ReconnectTimeout)
			c.options.Logger.DebugContext(ctx, "tunnel ended; retrying immediately: ", err)
			continue
		}
		c.options.Logger.DebugContext(ctx, "tunnel connection failed; retrying in ", reconnect.backoff, ": ", err)
		if !c.waitClientReconnectBackoff(ctx, &reconnect) {
			return
		}
		reconnect.attemptFailed()
	}
}

func (c *Client) discardWebSession(web *webSession) *webSession {
	c.releaseWebSession(web)
	return nil
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
	reason := TunnelEventInitial
	if reestablishment {
		reason = TunnelEventReestablishment
	}
	configuration := c.setTunnelConfiguration(session.TunnelConfiguration())
	if !c.publishCurrentSession(ctx, session) {
		c.clearCurrentSession(session)
		return false, E.Errors(session.Close(), ErrClientClosed)
	}
	c.publishTunnelEvent(reason, configuration)
	if reason == TunnelEventInitial {
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
	// The address the gateway assigned belonged to this session, and the next
	// session may be handed a different one, so a caller that programmed a TUN
	// device from the configuration hears that it no longer applies.
	c.setTunnelConfiguration(TunnelConfiguration{})
	c.publishTunnelEvent(TunnelEventDisconnect, TunnelConfiguration{})
	if sessionErr == nil {
		sessionErr = E.New("tunnel ended without an error")
	}
	return true, sessionErr
}

func (c *Client) waitClientReconnectBackoff(ctx context.Context, reconnect *reconnectState) bool {
	wait := reconnect.backoff
	if reconnect.reconnecting {
		if reconnect.timeoutRemaining <= 0 {
			c.setTerminalError(ErrReconnectTimeout)
			return false
		}
		wait = min(wait, reconnect.timeoutRemaining)
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		if reconnect.reconnecting {
			reconnect.timeoutRemaining -= wait
		}
		return true
	}
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
