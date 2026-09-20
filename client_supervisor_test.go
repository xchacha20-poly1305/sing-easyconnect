package easyconnect

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReconnectStateBacksOffToMaximum(t *testing.T) {
	t.Parallel()
	reconnect := newReconnectState()
	require.Equal(t, clientReconnectInitialBackoff, reconnect.backoff)
	reconnect.attemptFailed()
	require.Equal(t, 2*clientReconnectInitialBackoff, reconnect.backoff)
	for range 10 {
		reconnect.attemptFailed()
	}
	require.Equal(t, clientReconnectMaximumBackoff, reconnect.backoff)
}

func TestReconnectStateTunnelLostStartsReconnectBudget(t *testing.T) {
	t.Parallel()
	reconnect := newReconnectState()
	reconnect.attemptFailed()
	reconnect.tunnelLost(time.Minute)
	require.True(t, reconnect.established)
	require.True(t, reconnect.reconnecting)
	require.Equal(t, time.Minute, reconnect.timeoutRemaining)
	require.Equal(t, clientReconnectInitialBackoff, reconnect.backoff)
}

func TestWaitClientReconnectBackoffSpendsReconnectBudget(t *testing.T) {
	t.Parallel()
	client := &Client{stateChanged: make(chan struct{})}
	reconnect := newReconnectState()
	reconnect.tunnelLost(3 * time.Millisecond)
	reconnect.backoff = time.Millisecond
	require.True(t, client.waitClientReconnectBackoff(t.Context(), &reconnect))
	require.Equal(t, 2*time.Millisecond, reconnect.timeoutRemaining)
	require.NoError(t, client.terminalError)
}

func TestWaitClientReconnectBackoffFailsOnExhaustedBudget(t *testing.T) {
	t.Parallel()
	client := &Client{stateChanged: make(chan struct{})}
	reconnect := newReconnectState()
	reconnect.tunnelLost(0)
	require.False(t, client.waitClientReconnectBackoff(t.Context(), &reconnect))
	require.ErrorIs(t, client.terminalError, ErrReconnectTimeout)
}

func TestWaitClientReconnectBackoffStopsWithContext(t *testing.T) {
	t.Parallel()
	client := &Client{stateChanged: make(chan struct{})}
	reconnect := newReconnectState()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.False(t, client.waitClientReconnectBackoff(ctx, &reconnect))
}
