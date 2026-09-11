package easyconnect

import (
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// stalledConn stands in for an upload connection the path stopped forwarding:
// the write reaches the socket and never completes. It takes no deadline, so
// nothing but the test releases it.
type stalledConn struct {
	net.Conn
	writing   chan struct{}
	released  chan struct{}
	writeOnce sync.Once
}

func (c *stalledConn) SetWriteDeadline(time.Time) error { return nil }

func (c *stalledConn) Write(data []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writing) })
	<-c.released
	return len(data), nil
}

func (c *stalledConn) Close() error { return nil }

func newWriterTestClient(t *testing.T, queueLength uint32) *Client {
	t.Helper()
	client, err := NewClient(ClientOptions{
		Context:     t.Context(),
		Server:      "https://vpn.example.edu",
		Username:    "user",
		Password:    "password",
		Device:      "linux",
		QueueLength: queueLength,
		Logger:      logger.NOP(),
	})
	require.NoError(t, err)
	return client
}

// newWriterTestSession builds a tunnel session whose upload channel accepts one
// write and then stalls, with only the outgoing queue and the writer goroutine
// wired up.
func newWriterTestSession(t *testing.T, queueLength uint32) (*tunnelSession, *stalledConn) {
	t.Helper()
	upload := &stalledConn{
		writing:  make(chan struct{}),
		released: make(chan struct{}),
	}
	session := &tunnelSession{
		client:   newWriterTestClient(t, queueLength),
		done:     make(chan error, 1),
		upload:   upload,
		outgoing: newDataPacketQueue[*buf.Buffer](int(queueLength)),
	}
	session.ready.Store(true)
	return session, upload
}

func TestOutboundDataPacketsNeverWaitForTheUploadChannel(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		const queueLength = 2
		session, upload := newWriterTestSession(t, queueLength)
		session.running.Go(session.runOutgoingDataPacketWriter)

		// The first packet reaches the stalled write and stays there.
		require.NoError(t, session.EnqueueDataPacketBuffers(newPacketBuffersFrom([][]byte{{1}})))
		<-upload.writing

		// Everything after it fills the queue and is then dropped, but no
		// caller waits: a packet forwarding loop must not stop on a stalled
		// tunnel, since it carries every other flow too.
		for range queueLength + 3 {
			require.NoError(t, session.EnqueueDataPacketBuffers(newPacketBuffersFrom([][]byte{{2}})))
		}
		synctest.Wait()
		require.EqualValues(t, 3, session.client.DroppedOutgoingDataPackets())

		close(upload.released)
		session.outgoing.Close()
		session.running.Wait()
	})
}

func TestOutboundDataPacketsAreReleasedWhenTheSessionEnds(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		session, upload := newWriterTestSession(t, 4)
		session.running.Go(session.runOutgoingDataPacketWriter)

		require.NoError(t, session.EnqueueDataPacketBuffers(newPacketBuffersFrom([][]byte{{1}})))
		<-upload.writing
		require.NoError(t, session.EnqueueDataPacketBuffers(newPacketBuffersFrom([][]byte{{2}})))

		session.outgoing.Close()
		require.ErrorIs(t, session.EnqueueDataPacketBuffers(newPacketBuffersFrom([][]byte{{3}})), ErrDataChannelNotReady)
		close(upload.released)
		session.running.Wait()
		require.EqualValues(t, 2, session.client.DroppedOutgoingDataPackets())
	})
}

// A session can be closed between connecting and starting, before the writer
// goroutine exists to drain what the queue holds.
func TestOutboundDataPacketsAreReleasedWhenTheSessionNeverStarted(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		session, _ := newWriterTestSession(t, 4)
		require.NoError(t, session.EnqueueDataPacketBuffers(newPacketBuffersFrom([][]byte{{1}})))
		require.NoError(t, session.Close())
		require.Zero(t, session.outgoing.Pop(0))
	})
}
