package easyconnect

import (
	E "github.com/sagernet/sing/common/exceptions"
)

var (
	ErrMissingServer          = E.New("missing easyconnect server")
	ErrMissingDevice          = E.New("missing easyconnect device")
	ErrMissingCredentials     = E.New("missing easyconnect credentials")
	ErrClientClosed           = E.New("client is closed")
	ErrClientSuspended        = E.New("client is suspended")
	ErrDataChannelNotReady    = E.New("data channel is not ready")
	ErrAuthenticationFailed   = E.New("authentication failed")
	ErrSessionRejected        = E.New("session rejected")
	ErrSessionTimeout         = E.New("session timed out")
	ErrDataChannelTimeout     = E.New("data channel timed out")
	ErrProtocolNotSupported   = E.New("protocol behavior is not supported")
	ErrMaterialSourceConflict = E.New("material path and content are both set")
	ErrInvalidTLSMaterial     = E.New("invalid easyconnect TLS material")
	ErrReconnectTimeout       = E.New("reconnect timeout exceeded")
	errTunnelConfiguration    = E.New("tunnel configuration callback failed")
)

type TerminalError struct {
	err error
}

func (t *TerminalError) Error() string {
	return t.err.Error()
}

func (t *TerminalError) Unwrap() error {
	return t.err
}

func (t *TerminalError) Terminal() bool {
	return true
}

func markTerminal(err error) error {
	if err == nil {
		return nil
	}
	return &TerminalError{err: err}
}
