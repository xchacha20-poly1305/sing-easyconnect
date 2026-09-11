package easyconnect

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"

	E "github.com/sagernet/sing/common/exceptions"
)

// Wire formats of the Sangfor EasyConnect data plane.
//
// Every tunnel connection opens with a canned TLS 1.0 ClientHello and answers
// the server hello with a compiled-in CCS record. Nothing after that is TLS:
// the connections carry fixed-size fourcc messages.

const (
	// SessionIDLength is the length of the ASCII hex session prefix carried in
	// every tunnel message, taken from the conf.csp sslctx blob.
	SessionIDLength = 16

	timqMessageLength = 28
	ackqMessageLength = 60
	jjyyBodyLength    = 60
	jjyyTailLength    = 11
	aabbMessageLength = 40
	ipcpHeaderLength  = 12

	// maximumIPCPPayloadLength is the largest IPv4 datagram an IPCP frame can
	// carry, the range of the IPv4 total length field. A frame that claims more
	// is a desynchronized stream, and reading it would allocate whatever the
	// length field asked for.
	maximumIPCPPayloadLength = 65535
)

// TIMQ message types on the TCP keepalive channel.
const (
	timqTypeHeartbeat uint32 = 1
	timqTypeHandshake uint32 = 4
)

// ACKQ message types, the jump table of TimeQry::ProcessServerMsg. Types 1 and
// 2 are both heartbeat replies; the gateway also speaks unprompted, to end the
// session on timeout (3) or to hand out a new one (4).
const (
	ackqTypeHeartbeatExtend uint32 = 1
	ackqTypeHeartbeatReply  uint32 = 2
	ackqTypeTimeout         uint32 = 3
	ackqTypeNewSession      uint32 = 4
	ackqTypeHandshakeReply  uint32 = 5
)

// JJYY message types, one per MakeTunnel connection.
const (
	jjyyTypeCommand uint32 = 0
	jjyyTypeUpload  uint32 = 5
	jjyyTypeReceive uint32 = 6
)

// AABB reply types, indexed differently from the JJYY type that requested them.
const (
	aabbTypeCommand uint32 = 0
	aabbTypeReceive uint32 = 1
	aabbTypeUpload  uint32 = 2
)

var (
	magicTIMQ = [4]byte{'T', 'I', 'M', 'Q'}
	magicACKQ = [4]byte{'A', 'C', 'K', 'Q'}
	magicJJYY = [4]byte{'J', 'J', 'Y', 'Y'}
	magicAABB = [4]byte{'A', 'A', 'B', 'B'}
	magicIPCP = [4]byte{'I', 'P', 'C', 'P'}
)

type sessionID [SessionIDLength]byte

func parseSessionID(text string) (sessionID, error) {
	var id sessionID
	if len(text) != SessionIDLength {
		return id, E.New("invalid session id length ", len(text))
	}
	_, err := hex.DecodeString(text)
	if err != nil {
		return id, E.Cause(err, "invalid session id")
	}
	copy(id[:], text)
	return id, nil
}

func (id sessionID) String() string {
	return string(id[:])
}

// writeTIMQ writes a keepalive request.
// Fields are big-endian, unlike every other message in this protocol.
func writeTIMQ(writer io.Writer, messageType uint32, sequence uint32, session sessionID) error {
	var message [timqMessageLength]byte
	copy(message[0:4], magicTIMQ[:])
	binary.BigEndian.PutUint32(message[4:8], messageType)
	binary.BigEndian.PutUint32(message[8:12], sequence)
	copy(message[12:28], session[:])
	_, err := writer.Write(message[:])
	return err
}

type ackqMessage struct {
	Type     uint32
	Sequence uint32
	Extra    uint32
	Session  sessionID
}

func readACKQ(reader io.Reader) (ackqMessage, error) {
	var message [ackqMessageLength]byte
	_, err := io.ReadFull(reader, message[:])
	if err != nil {
		return ackqMessage{}, err
	}
	if !bytes.HasPrefix(message[:], magicACKQ[:]) {
		return ackqMessage{}, E.New("invalid ACKQ magic ", string(message[0:4]))
	}
	reply := ackqMessage{
		Type:     binary.BigEndian.Uint32(message[4:8]),
		Sequence: binary.BigEndian.Uint32(message[8:12]),
		Extra:    binary.BigEndian.Uint32(message[12:16]),
	}
	copy(reply.Session[:], message[16:32])
	return reply, nil
}

// writeJJYY writes the channel announcement of one L3VPN connection.
// The 60-byte body travels inside a TLS application data record header that the
// gateway never decrypts, and an 11-byte tail follows outside of it.
func writeJJYY(writer io.Writer, messageType uint32, session sessionID, address uint32) error {
	var message [5 + jjyyBodyLength + jjyyTailLength]byte
	message[0] = 0x17 // application data
	message[1] = 0x03
	message[2] = 0x01 // TLS 1.0
	binary.BigEndian.PutUint16(message[3:5], jjyyBodyLength)
	body := message[5 : 5+jjyyBodyLength]
	copy(body[3:7], magicJJYY[:])
	binary.LittleEndian.PutUint32(body[7:11], messageType)
	copy(body[43:59], session[:])
	tail := message[5+jjyyBodyLength:]
	binary.LittleEndian.PutUint32(tail[7:11], address)
	_, err := writer.Write(message[:])
	return err
}

type aabbMessage struct {
	Type uint32
	// Command reply fields, only meaningful on the command channel.
	Address      [4]byte
	Encryption   uint32
	LocalAddress [4]byte
	UDPPort      uint32
	Compression  uint32
}

func readAABB(reader io.Reader) (aabbMessage, error) {
	var message [aabbMessageLength]byte
	_, err := io.ReadFull(reader, message[:])
	if err != nil {
		return aabbMessage{}, err
	}
	if !bytes.HasPrefix(message[:], magicAABB[:]) {
		return aabbMessage{}, E.New("invalid AABB magic ", string(message[0:4]))
	}
	reply := aabbMessage{
		Type:        binary.LittleEndian.Uint32(message[4:8]),
		Address:     [4]byte(message[8:12]),
		Encryption:  binary.LittleEndian.Uint32(message[12:16]),
		UDPPort:     binary.LittleEndian.Uint32(message[20:24]),
		Compression: binary.LittleEndian.Uint32(message[24:28]),
	}
	copy(reply.LocalAddress[:], message[16:20])
	return reply, nil
}

// encodeIPCPHeader fills the 12-byte frame header that precedes every IPv4
// datagram on the upload and receive channels.
func encodeIPCPHeader(header []byte, payloadLength int) {
	copy(header[0:4], magicIPCP[:])
	binary.LittleEndian.PutUint32(header[4:8], uint32(ipcpHeaderLength+payloadLength))
	binary.LittleEndian.PutUint32(header[8:12], 0)
}

func readIPCPHeader(reader io.Reader) (payloadLength int, err error) {
	var header [ipcpHeaderLength]byte
	_, err = io.ReadFull(reader, header[:])
	if err != nil {
		return 0, err
	}
	if !bytes.HasPrefix(header[:], magicIPCP[:]) {
		return 0, E.New("invalid IPCP magic ", hex.EncodeToString(header[0:4]))
	}
	frameLength := binary.LittleEndian.Uint32(header[4:8])
	if frameLength < ipcpHeaderLength {
		return 0, E.New("invalid IPCP frame length ", frameLength)
	}
	payloadLength = int(frameLength) - ipcpHeaderLength
	if payloadLength > maximumIPCPPayloadLength {
		return 0, E.New("oversized IPCP frame of ", payloadLength, " bytes")
	}
	return payloadLength, nil
}
