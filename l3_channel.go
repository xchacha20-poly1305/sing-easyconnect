package easyconnect

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

func (c *Client) dialL3Channel(
	ctx context.Context,
	destination M.Socksaddr,
	session sessionID,
	channelType uint32,
	address uint32,
) (net.Conn, aabbMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, c.options.KeepAliveTimeout)
	defer cancel()
	conn, err := dialCamouflagedConn(ctx, c.options.Dialer, destination, camouflageRandomL3VPN, camouflageL3SessionPrefix)
	if err != nil {
		return nil, aabbMessage{}, err
	}
	reply, err := announceL3Channel(ctx, conn, session, channelType, address)
	if err != nil {
		conn.Close()
		return nil, aabbMessage{}, err
	}
	return conn, reply, nil
}

func announceL3Channel(ctx context.Context, conn net.Conn, session sessionID, channelType uint32, address uint32) (aabbMessage, error) {
	if ctx.Done() != nil {
		stopHandshakeCancel := context.AfterFunc(ctx, func() {
			conn.Close()
		})
		defer stopHandshakeCancel()
	}
	err := writeJJYY(conn, channelType, session, address)
	if err != nil {
		return aabbMessage{}, E.Cause(err, "write JJYY type ", channelType)
	}
	reply, err := readAABB(conn)
	if err != nil {
		return aabbMessage{}, E.Cause(err, "read AABB type ", channelType)
	}
	expectedType, err := expectedAABBType(channelType)
	if err != nil {
		return aabbMessage{}, err
	}
	if reply.Type != expectedType {
		return aabbMessage{}, E.Extend(ErrSessionRejected, "AABB type ", reply.Type, " on channel type ", channelType)
	}
	return reply, nil
}

func expectedAABBType(channelType uint32) (uint32, error) {
	switch channelType {
	case jjyyTypeCommand:
		return aabbTypeCommand, nil
	case jjyyTypeUpload:
		return aabbTypeUpload, nil
	case jjyyTypeReceive:
		return aabbTypeReceive, nil
	default:
		return 0, E.New("unknown channel type ", channelType)
	}
}

func channelAddress(address netip.Addr) uint32 {
	if !address.Is4() {
		return 0
	}
	octets := address.As4()
	return binary.BigEndian.Uint32(octets[:])
}

func readDataPacket(reader io.Reader, encoding payloadEncoding) (*buf.Buffer, error) {
	payloadLength, err := readIPCPHeader(reader)
	if err != nil {
		return nil, err
	}
	packetBuffer := newPacketBuffer(payloadLength)
	_, err = packetBuffer.ReadFullFrom(reader, payloadLength)
	if err != nil {
		packetBuffer.Release()
		return nil, err
	}
	encoding.apply(packetBuffer.Bytes())
	return packetBuffer, nil
}

func frameDataPacket(packetBuffer *buf.Buffer, encoding payloadEncoding) *buf.Buffer {
	packetBuffer = requireHeadroom(packetBuffer)
	encoding.apply(packetBuffer.Bytes())
	payloadLength := packetBuffer.Len()
	encodeIPCPHeader(packetBuffer.ExtendHeader(ipcpHeaderLength), payloadLength)
	return packetBuffer
}
