package easyconnect

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCamouflageClientHello(t *testing.T) {
	t.Parallel()
	session := mustSessionID(t, "0123456789abcdef")
	helloBuffer := camouflageClientHello(camouflageRandomTCP, camouflageSessionID([]byte(session.String())))
	defer helloBuffer.Release()
	hello := helloBuffer.Bytes()

	require.Len(t, hello, camouflageClientHelloLength)
	require.Equal(t, []byte{0x16, 0x03, 0x01}, hello[:3])
	require.Equal(t, len(hello)-5, int(binary.BigEndian.Uint16(hello[3:5])))
	require.Equal(t, byte(0x01), hello[5])

	random := hello[11:43]
	require.Equal(t, camouflageRandomTCP, random[31])
	require.Equal(t, byte(camouflageSessionIDLength), hello[43])

	sessionIdentifier := hello[44 : 44+camouflageSessionIDLength]
	require.Equal(t, session.String(), string(sessionIdentifier[:16]))
	require.Equal(t, byte('@'), sessionIdentifier[16])
	require.Equal(t, []byte{0x00, 0x02, 0x00, 0x39, 0x01, 0x00}, hello[44+camouflageSessionIDLength:])
}

func TestCamouflageL3SessionID(t *testing.T) {
	t.Parallel()
	require.Equal(t, camouflageServerAck[44:76], camouflageSessionID(camouflageL3SessionPrefix))
}

func TestReadCamouflageServerAck(t *testing.T) {
	t.Parallel()

	t.Run("reference vector", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, readCamouflageServerAck(bytes.NewReader(camouflageServerAck)))
	})

	t.Run("longer server hello", func(t *testing.T) {
		t.Parallel()
		// A gateway that pads its server hello must not push the rest of the
		// reply into the first tunnel message.
		serverHello := camouflageServerAck[:5+0x4a]
		extended := slices.Concat(serverHello, []byte{0x00, 0x00}, camouflageServerAck[5+0x4a:])
		binary.BigEndian.PutUint16(extended[3:5], 0x4a+2)
		reader := bytes.NewReader(extended)
		require.NoError(t, readCamouflageServerAck(reader))
		require.Equal(t, 0, reader.Len())
	})

	t.Run("wrong record type", func(t *testing.T) {
		t.Parallel()
		reply := bytes.Clone(camouflageServerAck)
		reply[0] = 0x15 // alert
		require.ErrorIs(t, readCamouflageServerAck(bytes.NewReader(reply)), ErrProtocolNotSupported)
	})

	t.Run("wrong handshake type", func(t *testing.T) {
		t.Parallel()
		reply := bytes.Clone(camouflageServerAck)
		reply[5] = 0x01 // client hello
		require.ErrorIs(t, readCamouflageServerAck(bytes.NewReader(reply)), ErrProtocolNotSupported)
	})
}
