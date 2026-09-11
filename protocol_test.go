package easyconnect

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustSessionID(t *testing.T, text string) sessionID {
	t.Helper()
	session, err := parseSessionID(text)
	require.NoError(t, err)
	return session
}

func TestWriteTIMQ(t *testing.T) {
	t.Parallel()
	session := mustSessionID(t, "0123456789abcdef")
	var buffer bytes.Buffer
	require.NoError(t, writeTIMQ(&buffer, timqTypeHandshake, 0x11223344, session))

	expected := make([]byte, timqMessageLength)
	copy(expected, magicTIMQ[:])
	binary.BigEndian.PutUint32(expected[4:8], timqTypeHandshake)
	binary.BigEndian.PutUint32(expected[8:12], 0x11223344)
	copy(expected[12:28], session[:])
	require.Equal(t, expected, buffer.Bytes())
}

func TestParseACKQ(t *testing.T) {
	t.Parallel()

	t.Run("heartbeat reply", func(t *testing.T) {
		t.Parallel()
		message := make([]byte, ackqMessageLength)
		copy(message, magicACKQ[:])
		binary.BigEndian.PutUint32(message[4:8], ackqTypeHeartbeatReply)
		binary.BigEndian.PutUint32(message[8:12], 4321)
		binary.BigEndian.PutUint32(message[12:16], 7)
		copy(message[16:32], "0123456789abcdef")

		reply, err := readACKQ(bytes.NewReader(message))
		require.NoError(t, err)
		require.Equal(t, ackqMessage{
			Type:     ackqTypeHeartbeatReply,
			Sequence: 4321,
			Extra:    7,
			Session:  mustSessionID(t, "0123456789abcdef"),
		}, reply)
	})

	t.Run("wrong magic", func(t *testing.T) {
		t.Parallel()
		message := make([]byte, ackqMessageLength)
		copy(message, "XXXX")
		_, err := readACKQ(bytes.NewReader(message))
		require.ErrorContains(t, err, "invalid ACKQ magic")
	})

	t.Run("truncated", func(t *testing.T) {
		t.Parallel()
		_, err := readACKQ(bytes.NewReader(make([]byte, ackqMessageLength-1)))
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})
}

func TestWriteJJYY(t *testing.T) {
	t.Parallel()
	session := mustSessionID(t, "0123456789abcdef")
	address := netip.MustParseAddr("10.1.183.174")
	var buffer bytes.Buffer
	require.NoError(t, writeJJYY(&buffer, jjyyTypeUpload, session, channelAddress(address)))

	expected := make([]byte, 5+jjyyBodyLength+jjyyTailLength)
	expected[0] = 0x17
	expected[1] = 0x03
	expected[2] = 0x01
	binary.BigEndian.PutUint16(expected[3:5], jjyyBodyLength)
	copy(expected[8:12], magicJJYY[:])
	binary.LittleEndian.PutUint32(expected[12:16], jjyyTypeUpload)
	copy(expected[48:64], session[:])
	binary.LittleEndian.PutUint32(expected[5+jjyyBodyLength+7:], channelAddress(address))
	require.Equal(t, expected, buffer.Bytes())
}

func TestParseAABB(t *testing.T) {
	t.Parallel()

	t.Run("command reply", func(t *testing.T) {
		t.Parallel()
		message := make([]byte, aabbMessageLength)
		copy(message, magicAABB[:])
		binary.LittleEndian.PutUint32(message[4:8], aabbTypeCommand)
		copy(message[8:12], []byte{10, 1, 183, 174})
		binary.LittleEndian.PutUint32(message[12:16], 1)
		copy(message[16:20], []byte{10, 1, 253, 6})
		binary.LittleEndian.PutUint32(message[20:24], 0)
		binary.LittleEndian.PutUint32(message[24:28], 3)

		reply, err := readAABB(bytes.NewReader(message))
		require.NoError(t, err)
		require.Equal(t, aabbMessage{
			Type:         aabbTypeCommand,
			Address:      [4]byte{10, 1, 183, 174},
			Encryption:   1,
			LocalAddress: [4]byte{10, 1, 253, 6},
			UDPPort:      0,
			Compression:  3,
		}, reply)
		require.Equal(t, netip.MustParseAddr("10.1.183.174"), netip.AddrFrom4(reply.Address))
	})

	t.Run("wrong magic", func(t *testing.T) {
		t.Parallel()
		message := make([]byte, aabbMessageLength)
		copy(message, "XXXX")
		_, err := readAABB(bytes.NewReader(message))
		require.ErrorContains(t, err, "invalid AABB magic")
	})
}

func TestIPCPHeader(t *testing.T) {
	t.Parallel()
	header := make([]byte, ipcpHeaderLength)
	encodeIPCPHeader(header, 40)
	require.Equal(t, "IPCP", string(header[:4]))

	payloadLength, err := readIPCPHeader(bytes.NewReader(header))
	require.NoError(t, err)
	require.Equal(t, 40, payloadLength)

	binary.LittleEndian.PutUint32(header[4:8], 4)
	_, err = readIPCPHeader(bytes.NewReader(header))
	require.ErrorContains(t, err, "invalid IPCP frame length")

	binary.LittleEndian.PutUint32(header[4:8], ipcpHeaderLength+maximumIPCPPayloadLength+1)
	_, err = readIPCPHeader(bytes.NewReader(header))
	require.ErrorContains(t, err, "oversized IPCP frame")
}

func TestPayloadEncoding(t *testing.T) {
	t.Parallel()

	t.Run("xor", func(t *testing.T) {
		t.Parallel()
		encoding, err := parsePayloadEncoding(payloadEncryptionXOR, payloadCompressionNone)
		require.NoError(t, err)
		payload := []byte{0x45, 0x00, 0x00, 0x54}
		original := append([]byte(nil), payload...)
		encoding.apply(payload)
		require.Equal(t, byte(0x05), payload[0])
		encoding.apply(payload)
		require.Equal(t, original, payload)
	})

	t.Run("plain", func(t *testing.T) {
		t.Parallel()
		encoding, err := parsePayloadEncoding(payloadEncryptionNone, payloadCompressionNone)
		require.NoError(t, err)
		payload := []byte{0x45, 0x00, 0x00, 0x54}
		encoding.apply(payload)
		require.Equal(t, []byte{0x45, 0x00, 0x00, 0x54}, payload)
	})

	t.Run("unknown encryption", func(t *testing.T) {
		t.Parallel()
		_, err := parsePayloadEncoding(2, payloadCompressionNone)
		require.ErrorIs(t, err, ErrProtocolNotSupported)
		require.True(t, isTerminalError(err))
	})

	t.Run("unknown compression", func(t *testing.T) {
		t.Parallel()
		_, err := parsePayloadEncoding(payloadEncryptionXOR, 1)
		require.ErrorIs(t, err, ErrProtocolNotSupported)
		require.True(t, isTerminalError(err))
	})
}

func TestParseSessionID(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name    string
		input   string
		want    string
		wantErr string
	}{
		{name: "valid", input: "0123456789abcdef", want: "0123456789abcdef"},
		{name: "too short", input: "0123456789abcde", wantErr: "invalid session id length"},
		{name: "non hex", input: "0123456789abcdeg", wantErr: "invalid session id"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			session, err := parseSessionID(testCase.input)
			if testCase.wantErr != "" {
				require.ErrorContains(t, err, testCase.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.want, session.String())
		})
	}
}
