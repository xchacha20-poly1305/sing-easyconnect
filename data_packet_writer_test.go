package easyconnect

import (
	"testing"
	"testing/synctest"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// stalledSession stands in for a tunnel whose upload connection stopped
// draining, the state an evicted NAT entry leaves behind.
type stalledSession struct {
	clientSession
	writing  chan struct{}
	released chan struct{}
}

func (s *stalledSession) WriteDataPacketBuffers(packetBuffers []*buf.Buffer) error {
	close(s.writing)
	<-s.released
	buf.ReleaseMulti(packetBuffers)
	return nil
}

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

func TestOutboundDataPacketsNeverWaitForTheUploadChannel(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		const queueLength = 2
		client := newWriterTestClient(t, queueLength)
		session := &stalledSession{
			writing:  make(chan struct{}),
			released: make(chan struct{}),
		}
		client.outgoingDataPacketWriterDone = make(chan struct{})
		go client.runOutgoingDataPacketWriter()

		// The first packet reaches the stalled write and stays there.
		require.NoError(t, client.enqueueOutboundDataPacketBuffers(session, newPacketBuffersFrom([][]byte{{1}})))
		<-session.writing

		// Everything after it fills the queue and is then dropped, but no
		// caller waits: a packet forwarding loop must not stop on a stalled
		// tunnel, since it carries every other flow too.
		for range queueLength + 3 {
			require.NoError(t, client.enqueueOutboundDataPacketBuffers(session, newPacketBuffersFrom([][]byte{{2}})))
		}
		synctest.Wait()
		require.EqualValues(t, 3, client.DroppedOutgoingDataPackets())

		close(session.released)
		client.outgoingDataPackets.Close()
		<-client.outgoingDataPacketWriterDone
	})
}

func TestOutboundDataPacketsAreReleasedWhenTheClientCloses(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		client := newWriterTestClient(t, 4)
		session := &stalledSession{
			writing:  make(chan struct{}),
			released: make(chan struct{}),
		}
		client.outgoingDataPacketWriterDone = make(chan struct{})
		go client.runOutgoingDataPacketWriter()

		require.NoError(t, client.enqueueOutboundDataPacketBuffers(session, newPacketBuffersFrom([][]byte{{1}})))
		<-session.writing
		require.NoError(t, client.enqueueOutboundDataPacketBuffers(session, newPacketBuffersFrom([][]byte{{2}})))

		client.outgoingDataPackets.Close()
		require.ErrorIs(t, client.enqueueOutboundDataPacketBuffers(session, newPacketBuffersFrom([][]byte{{3}})), ErrClientClosed)
		close(session.released)
		<-client.outgoingDataPacketWriterDone
		require.EqualValues(t, 2, client.DroppedOutgoingDataPackets())
	})
}
