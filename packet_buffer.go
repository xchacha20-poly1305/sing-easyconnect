package easyconnect

import (
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
)

// PacketHeadroom is the space every data packet buffer must leave in front of
// the IPv4 datagram for the IPCP frame header.
const PacketHeadroom = ipcpHeaderLength

func newPacketBuffer(payloadSize int) *buf.Buffer {
	packetBuffer := buf.NewSize(PacketHeadroom + payloadSize)
	packetBuffer.Resize(PacketHeadroom, 0)
	return packetBuffer
}

func newPacketBufferFrom(payload []byte) *buf.Buffer {
	packetBuffer := newPacketBuffer(len(payload))
	_, _ = packetBuffer.Write(payload)
	return packetBuffer
}

func newPacketBuffersFrom(payloads [][]byte) []*buf.Buffer {
	return common.Map(payloads, newPacketBufferFrom)
}

func requireHeadroom(packetBuffer *buf.Buffer) *buf.Buffer {
	if packetBuffer.Start() >= PacketHeadroom {
		return packetBuffer
	}
	newBuffer := newPacketBufferFrom(packetBuffer.Bytes())
	packetBuffer.Release()
	return newBuffer
}
