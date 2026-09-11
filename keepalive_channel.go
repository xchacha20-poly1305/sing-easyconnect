package easyconnect

import (
	"context"
	"net"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// keepaliveChannel is the TCP module connection.
// It exchanges TIMQ and ACKQ messages that keep the gateway session alive,
// and its failure is how a dead gateway is noticed.
type keepaliveChannel struct {
	conn      net.Conn
	session   sessionID
	options   keepaliveOptions
	requested uint32
	logger    logger.ContextLogger
}

// keepaliveOptions are the settings of one keepalive channel.
// timeout bounds both one TIMQ/ACKQ exchange and, in dialKeepaliveChannel, the
// whole opening handshake: the TCP connect and the camouflage exchange included.
type keepaliveOptions struct {
	interval time.Duration
	timeout  time.Duration
	sequence keepaliveSequence
}

func dialKeepaliveChannel(
	ctx context.Context,
	dialer N.Dialer,
	destination M.Socksaddr,
	session sessionID,
	options keepaliveOptions,
	channelLogger logger.ContextLogger,
) (*keepaliveChannel, error) {
	ctx, cancel := context.WithTimeout(ctx, options.timeout)
	defer cancel()
	conn, err := dialCamouflagedConn(ctx, dialer, destination, camouflageRandomTCP, []byte(session.String()))
	if err != nil {
		return nil, err
	}
	channel := &keepaliveChannel{
		conn:    conn,
		session: session,
		options: options,
		logger:  channelLogger,
	}
	if ctx.Done() != nil {
		stopHandshakeCancel := context.AfterFunc(ctx, func() {
			_ = conn.Close()
		})
		defer stopHandshakeCancel()
	}
	err = channel.exchange(ctx, timqTypeHandshake)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return channel, nil
}

func (c *keepaliveChannel) run(ctx context.Context) error {
	timer := time.NewTimer(c.options.interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
		err := c.exchange(ctx, timqTypeHeartbeat)
		if err != nil {
			return err
		}
		timer.Reset(c.options.interval)
	}
}

func (c *keepaliveChannel) exchange(ctx context.Context, requestType uint32) error {
	c.requested = c.options.sequence.value()
	err := c.conn.SetWriteDeadline(time.Now().Add(c.options.timeout))
	if err != nil {
		return err
	}
	err = writeTIMQ(c.conn, requestType, c.requested, c.session)
	if err != nil {
		return E.Cause(err, "write TIMQ type ", requestType)
	}
	err = c.conn.SetReadDeadline(time.Now().Add(c.options.timeout))
	if err != nil {
		return err
	}
	for {
		reply, err := readACKQ(c.conn)
		if err != nil {
			return E.Cause(err, "read ACKQ for TIMQ type ", requestType)
		}
		if reply.Session != c.session {
			return E.Extend(ErrSessionRejected, "ACKQ session mismatch")
		}
		replied, handleErr := c.handleACKQ(ctx, reply, requestType)
		if handleErr != nil {
			return handleErr
		}
		if replied {
			return nil
		}
	}
}

func (c *keepaliveChannel) handleACKQ(ctx context.Context, reply ackqMessage, requestType uint32) (bool, error) {
	switch reply.Type {
	case ackqTypeHandshakeReply:
		if requestType != timqTypeHandshake {
			break
		}
		return c.acceptReply(reply)
	case ackqTypeHeartbeatExtend, ackqTypeHeartbeatReply:
		if requestType != timqTypeHeartbeat {
			break
		}
		if reply.Extra == 0 {
			// A heartbeat reply carries the seconds the session was extended by;
			// on zero the reference client stops its keepalive thread.
			return false, E.Extend(ErrSessionRejected, "gateway stopped extending the session")
		}
		return c.acceptReply(reply)
	case ackqTypeTimeout:
		return false, ErrSessionTimeout
	case ackqTypeNewSession:
		// The reference client answers this with ProcessNewSession.
		// Dropping the tunnel reaches the same place, since the supervisor authenticates
		// again from scratch.
		return false, E.Extend(ErrSessionRejected, "gateway handed out a new session")
	}
	c.logger.DebugContext(ctx, "ignoring ACKQ type ", reply.Type,
		" sequence ", reply.Sequence, " extra ", reply.Extra)
	return false, nil
}

func (c *keepaliveChannel) acceptReply(reply ackqMessage) (bool, error) {
	if reply.Sequence != c.requested {
		return false, E.Extend(ErrSessionRejected, "ACKQ sequence ", reply.Sequence, " for TIMQ sequence ", c.requested)
	}
	return true, nil
}

func (c *keepaliveChannel) Close() error {
	return c.conn.Close()
}
