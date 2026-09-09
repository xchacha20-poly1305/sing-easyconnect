package easyconnect

import (
	"context"
	"testing"

	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func TestHandleACKQ(t *testing.T) {
	t.Parallel()
	const sequence = 0x11223344
	for _, testCase := range []struct {
		name        string
		requestType uint32
		reply       ackqMessage
		wantReplied bool
		wantErr     error
	}{
		{
			name:        "handshake reply",
			requestType: timqTypeHandshake,
			reply:       ackqMessage{Type: ackqTypeHandshakeReply, Sequence: sequence},
			wantReplied: true,
		},
		{
			name:        "heartbeat reply extends the session",
			requestType: timqTypeHeartbeat,
			reply:       ackqMessage{Type: ackqTypeHeartbeatReply, Sequence: sequence, Extra: 60},
			wantReplied: true,
		},
		{
			name:        "heartbeat reply of the other type",
			requestType: timqTypeHeartbeat,
			reply:       ackqMessage{Type: ackqTypeHeartbeatExtend, Sequence: sequence, Extra: 60},
			wantReplied: true,
		},
		{
			name:        "heartbeat reply stops the session",
			requestType: timqTypeHeartbeat,
			reply:       ackqMessage{Type: ackqTypeHeartbeatReply, Sequence: sequence},
			wantErr:     ErrSessionRejected,
		},
		{
			name:        "sequence mismatch",
			requestType: timqTypeHeartbeat,
			reply:       ackqMessage{Type: ackqTypeHeartbeatReply, Sequence: sequence + 1, Extra: 60},
			wantErr:     ErrSessionRejected,
		},
		{
			name:        "gateway timeout",
			requestType: timqTypeHeartbeat,
			reply:       ackqMessage{Type: ackqTypeTimeout},
			wantErr:     ErrSessionTimeout,
		},
		{
			name:        "new session",
			requestType: timqTypeHeartbeat,
			reply:       ackqMessage{Type: ackqTypeNewSession},
			wantErr:     ErrSessionRejected,
		},
		{
			name:        "unknown type is skipped",
			requestType: timqTypeHeartbeat,
			reply:       ackqMessage{Type: 6, Sequence: sequence},
		},
		{
			name:        "handshake reply while waiting for a heartbeat",
			requestType: timqTypeHeartbeat,
			reply:       ackqMessage{Type: ackqTypeHandshakeReply, Sequence: sequence},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			channel := &keepaliveChannel{requested: sequence, logger: logger.NOP()}
			replied, err := channel.handleACKQ(context.Background(), testCase.reply, testCase.requestType)
			if testCase.wantErr != nil {
				require.ErrorIs(t, err, testCase.wantErr)
				require.False(t, replied)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.wantReplied, replied)
		})
	}
}
