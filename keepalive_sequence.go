package easyconnect

import (
	"math/rand/v2"
	"time"
)

const keepaliveSequenceDisguisedUptime = time.Hour

type keepaliveSequence struct {
	clientStart time.Time
}

func disguisedClientStart() time.Time {
	return time.Now().Add(-rand.N(keepaliveSequenceDisguisedUptime))
}

func (s keepaliveSequence) value() uint32 {
	return uint32(time.Since(s.clientStart).Seconds())
}
