package easyconnect

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestKeepaliveSequence(t *testing.T) {
	t.Parallel()

	t.Run("counts seconds since the client start", func(t *testing.T) {
		t.Parallel()
		sequence := keepaliveSequence{clientStart: time.Now().Add(-42 * time.Second)}
		require.Equal(t, uint32(42), sequence.value())
	})

	t.Run("disguised start stays below the claimed uptime", func(t *testing.T) {
		t.Parallel()
		// A disguised counter claims an uptime the reference client could
		// plausibly have, and says nothing about this process.
		sequence := keepaliveSequence{clientStart: disguisedClientStart()}
		require.Less(t, sequence.value(), uint32(keepaliveSequenceDisguisedUptime/time.Second))
	})

	t.Run("disguised channels differ", func(t *testing.T) {
		t.Parallel()
		// Distinct enough that two tunnels do not look like one client.
		var values [16]uint32
		for index := range values {
			values[index] = keepaliveSequence{clientStart: disguisedClientStart()}.value()
		}
		require.Greater(t, len(uniqueValues(values[:])), 1)
	})
}

func uniqueValues(values []uint32) map[uint32]struct{} {
	unique := make(map[uint32]struct{}, len(values))
	for _, value := range values {
		unique[value] = struct{}{}
	}
	return unique
}
