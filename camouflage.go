package easyconnect

import (
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// The gateway expects every tunnel connection to open with the TLS records
// that svpnservice has compiled in. They are OpenSSL 1.0.2 test vectors: no
// key exchange happens and nothing is ever encrypted, so the exchange is
// replayed byte for byte instead of running a TLS stack. The vectors live in
// camouflage/ as raw records; inspect them with `xxd`.
var (
	// camouflageClientSyn is the CCS record plus the canned 32-byte record the
	// client sends once the server hello arrives.
	//go:embed camouflage/client_syn.bin
	camouflageClientSyn []byte

	// camouflageServerAck is the compiled server hello vector, kept as the
	// reference for what the gateway answers with: a server hello record, a
	// change cipher spec record and the canned 32-byte record. The gateway
	// rewrites the session id of the server hello to echo the client, so the
	// reply is read record by record and only its layout is checked.
	//go:embed camouflage/server_hello.bin
	camouflageServerAck []byte

	// camouflageRandomPrefix is the hardcoded client random without its last
	// byte, which identifies the channel family.
	//go:embed camouflage/client_random.bin
	camouflageRandomPrefix []byte

	// camouflageSessionTemplate is the session id as it appears in the server
	// hello vector: a 16-byte prefix, the '@' separator, then a 15-byte tail
	// shared by every session id.
	//go:embed camouflage/session_id.bin
	camouflageSessionTemplate []byte
)

// camouflageSessionPrefix is the first half of the 32-byte camouflage session
// id: the ASCII hex gateway session on the TCP channel, and template bytes on
// the L3VPN connections, where the client does not send the gateway session id.
type camouflageSessionPrefix [camouflageSessionPrefixLength]byte

// camouflageSessionIdentifier is the session id a client hello carries: a
// prefix, the '@' separator and the tail shared by every session.
type camouflageSessionIdentifier [camouflageSessionIDLength]byte

var camouflageL3SessionPrefix = camouflageSessionPrefix(camouflageSessionTemplate[:camouflageSessionPrefixLength])

// Last byte of the client random, the only field that distinguishes the TCP
// module connection from the L3VPN connections.
const (
	camouflageRandomTCP   byte = 0x33
	camouflageRandomL3VPN byte = 0x43
)

// TLS record and handshake tags used by the camouflage exchange.
const (
	tlsRecordChangeCipherSpec byte = 0x14
	tlsRecordHandshake        byte = 0x16
	tlsHandshakeServerHello   byte = 0x02

	tlsRecordHeaderLength = 5
	// tlsMaximumRecordLength is the largest record TLS 1.0 may send. Nothing in
	// the camouflage exchange comes close; the bound is here so a desynchronized
	// stream fails instead of allocating whatever the length field claims.
	tlsMaximumRecordLength = 1 << 14
)

const (
	camouflageRandomLength        = 32
	camouflageSessionIDLength     = 32
	camouflageSessionPrefixLength = 16

	camouflageHelloBodyLength   = 2 + camouflageRandomLength + 1 + camouflageSessionIDLength + 4 + 2
	camouflageHandshakeLength   = 4 + camouflageHelloBodyLength
	camouflageClientHelloLength = 5 + camouflageHandshakeLength
)

func camouflageSessionID(prefix camouflageSessionPrefix) camouflageSessionIdentifier {
	sessionIdentifier := camouflageSessionIdentifier(camouflageSessionTemplate)
	copy(sessionIdentifier[:camouflageSessionPrefixLength], prefix[:])
	return sessionIdentifier
}

// camouflageClientHello builds the 82-byte hello: TLS 1.0, one cipher suite,
// no compression and no extensions. The caller owns the returned buffer.
func camouflageClientHello(randomSuffix byte, sessionIdentifier camouflageSessionIdentifier) *buf.Buffer {
	buffer := buf.NewSize(camouflageClientHelloLength)
	common.Must(common.Error(buffer.Write([]byte{0x16, 0x03, 0x01}))) // handshake record, TLS 1.0
	binary.BigEndian.PutUint16(buffer.Extend(2), camouflageHandshakeLength)
	common.Must(common.Error(buffer.Write([]byte{0x01, 0x00}))) // client hello, high byte of its 24-bit length
	binary.BigEndian.PutUint16(buffer.Extend(2), camouflageHelloBodyLength)
	common.Must(
		common.Error(buffer.Write([]byte{0x03, 0x01})), // TLS 1.0
		common.Error(buffer.Write(camouflageRandomPrefix)),
		buffer.WriteByte(randomSuffix),
		buffer.WriteByte(camouflageSessionIDLength),
		common.Error(buffer.Write(sessionIdentifier[:])),
		common.Error(buffer.Write([]byte{0x00, 0x02, 0x00, 0x39})), // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
		common.Error(buffer.Write([]byte{0x01, 0x00})),             // no compression
	)
	return buffer
}

func dialCamouflagedConn(ctx context.Context, dialer N.Dialer, destination M.Socksaddr, randomSuffix byte, sessionPrefix camouflageSessionPrefix) (net.Conn, error) {
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		return nil, err
	}
	if ctx.Done() != nil {
		stopHandshakeCancel := context.AfterFunc(ctx, func() {
			_ = conn.Close()
		})
		defer stopHandshakeCancel()
	}
	err = camouflageHandshake(conn, randomSuffix, sessionPrefix)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func readCamouflageServerAck(reader io.Reader) error {
	serverHello, err := readTLSRecord(reader, tlsRecordHandshake)
	if err != nil {
		return E.Cause(err, "read camouflage server hello")
	}
	if len(serverHello) == 0 || serverHello[0] != tlsHandshakeServerHello {
		return E.Extend(ErrProtocolNotSupported, "unexpected camouflage server hello ",
			hex.EncodeToString(serverHello[:min(8, len(serverHello))]))
	}
	_, err = readTLSRecord(reader, tlsRecordChangeCipherSpec)
	if err != nil {
		return E.Cause(err, "read camouflage server change cipher spec")
	}
	_, err = readTLSRecord(reader, tlsRecordHandshake)
	if err != nil {
		return E.Cause(err, "read camouflage server ack")
	}
	return nil
}

func readTLSRecord(reader io.Reader, recordType byte) ([]byte, error) {
	var header [tlsRecordHeaderLength]byte
	_, err := io.ReadFull(reader, header[:])
	if err != nil {
		return nil, err
	}
	if header[0] != recordType {
		return nil, E.Extend(ErrProtocolNotSupported, "unexpected camouflage record type ", header[0])
	}
	length := binary.BigEndian.Uint16(header[3:5])
	if length > tlsMaximumRecordLength {
		return nil, E.Extend(ErrProtocolNotSupported, "oversized camouflage record of ", length, " bytes")
	}
	payload := make([]byte, length)
	_, err = io.ReadFull(reader, payload)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func camouflageHandshake(conn net.Conn, randomSuffix byte, sessionPrefix camouflageSessionPrefix) error {
	clientHello := camouflageClientHello(randomSuffix, camouflageSessionID(sessionPrefix))
	defer clientHello.Release()
	_, err := clientHello.WriteTo(conn)
	if err != nil {
		return E.Cause(err, "write camouflage client hello")
	}
	err = readCamouflageServerAck(conn)
	if err != nil {
		return err
	}
	_, err = conn.Write(camouflageClientSyn)
	if err != nil {
		return E.Cause(err, "write camouflage client syn")
	}
	return nil
}
