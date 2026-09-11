package easyconnect

import (
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	// payloadEncryptionNone leaves the datagram in the clear.
	payloadEncryptionNone uint32 = 0
	// payloadEncryptionXOR is a single byte XOR over the datagram. svpnservice
	// also carries RC4 key material for an encoding never seen on the wire, so
	// every other enc value is refused instead of assumed to mean this one.
	payloadEncryptionXOR uint32 = 1

	// payloadCompressionNone is the only zip value observed, and it came with
	// uncompressed datagrams. What the value counts is unknown, so every other
	// one is refused: reading a compressed datagram as a plain one would
	// corrupt the tunnel silently.
	payloadCompressionNone uint32 = 3
)

const payloadObfuscationKey byte = 0x40

type payloadEncoding struct {
	obfuscated bool
}

func parsePayloadEncoding(encryption uint32, compression uint32) (payloadEncoding, error) {
	if compression != payloadCompressionNone {
		return payloadEncoding{}, markTerminal(E.Extend(ErrProtocolNotSupported, "unsupported payload compression ", compression))
	}
	switch encryption {
	case payloadEncryptionNone:
		return payloadEncoding{}, nil
	case payloadEncryptionXOR:
		return payloadEncoding{obfuscated: true}, nil
	default:
		return payloadEncoding{}, markTerminal(E.Extend(ErrProtocolNotSupported, "unsupported payload encryption ", encryption))
	}
}

func (e payloadEncoding) apply(payload []byte) {
	if !e.obfuscated {
		return
	}
	xorKey(payload, payloadObfuscationKey)
}
