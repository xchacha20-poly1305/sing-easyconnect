package easyconnect

import (
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

type outboundDataPacket struct {
	session      clientSession
	packetBuffer *buf.Buffer
}

func (c *Client) enqueueOutboundDataPacketBuffers(session clientSession, packetBuffers []*buf.Buffer) error {
	packets := make([]outboundDataPacket, len(packetBuffers))
	for index, packetBuffer := range packetBuffers {
		packets[index] = outboundDataPacket{
			session:      session,
			packetBuffer: packetBuffer,
		}
	}
	pushed := c.outgoingDataPackets.TryPushBatch(packets)
	if pushed == len(packets) {
		return nil
	}
	c.dropOutboundDataPackets(packets[pushed:])
	if c.outgoingDataPackets.Closed() {
		return ErrClientClosed
	}
	return nil
}

func (c *Client) runOutgoingDataPacketWriter() {
	defer close(c.outgoingDataPacketWriterDone)
	defer c.outgoingDataPackets.Drain(func(packet outboundDataPacket) {
		packet.packetBuffer.Release()
	})
	for {
		packets := c.outgoingDataPackets.Pop(0)
		if len(packets) == 0 {
			if c.outgoingDataPackets.Closed() {
				return
			}
			<-c.outgoingDataPackets.Wake()
			continue
		}
		if c.outgoingDataPackets.Closed() {
			c.dropOutboundDataPackets(packets)
			continue
		}
		for len(packets) > 0 {
			session := packets[0].session
			count := 1
			for count < len(packets) && packets[count].session == session {
				count++
			}
			c.writeQueuedOutboundDataPackets(session, packets[:count])
			packets = packets[count:]
		}
	}
}

func (c *Client) writeQueuedOutboundDataPackets(session clientSession, packets []outboundDataPacket) {
	packetBuffers := make([]*buf.Buffer, len(packets))
	for index, packet := range packets {
		packetBuffers[index] = packet.packetBuffer
	}
	// The session releases the buffers and fails itself on a write error, which
	// the supervisor turns into a reconnection.
	err := session.WriteDataPacketBuffers(packetBuffers)
	if err != nil {
		c.options.Logger.Debug(E.Cause(err, "write outbound data packets"))
	}
}

func (c *Client) dropOutboundDataPackets(packets []outboundDataPacket) {
	for _, packet := range packets {
		packet.packetBuffer.Release()
	}
	c.droppedOutgoingDataPackets.Add(uint64(len(packets)))
}
