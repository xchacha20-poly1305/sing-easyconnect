package easyconnect

import (
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

func (s *tunnelSession) EnqueueDataPacketBuffers(packetBuffers []*buf.Buffer) error {
	pushed := s.outgoing.TryPushBatch(packetBuffers)
	if pushed == len(packetBuffers) {
		return nil
	}
	s.dropOutboundDataPackets(packetBuffers[pushed:])
	if s.outgoing.Closed() {
		return ErrDataChannelNotReady
	}
	return nil
}

func (s *tunnelSession) runOutgoingDataPacketWriter() {
	defer s.outgoing.Drain((*buf.Buffer).Release)
	var packetBuffers []*buf.Buffer
	for {
		packetBuffers = s.outgoing.PopInto(packetBuffers, 0)
		if len(packetBuffers) == 0 {
			if s.outgoing.Closed() {
				return
			}
			<-s.outgoing.Wake()
			continue
		}
		if s.outgoing.Closed() {
			s.dropOutboundDataPackets(packetBuffers)
			continue
		}
		// The session releases the buffers and fails itself on a write error,
		// which the supervisor turns into a reconnection.
		err := s.WriteDataPacketBuffers(packetBuffers)
		if err != nil {
			s.client.options.Logger.Debug(E.Cause(err, "write outbound data packets"))
		}
	}
}

func (s *tunnelSession) dropOutboundDataPackets(packetBuffers []*buf.Buffer) {
	buf.ReleaseMulti(packetBuffers)
	s.client.droppedOutgoingDataPackets.Add(uint64(len(packetBuffers)))
}
