package easyconnect

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkEncryptionXor(b *testing.B) {
	encoder, err := parsePayloadEncoding(payloadEncryptionXOR, payloadCompressionNone)
	require.NoError(b, err)

	cases := []struct {
		name string
		size int
	}{
		{"1400", 1400},
		{"1024", 1024},
		{"8192", 8192},
		{"16384", 16384},
		{"32768", 32768},
	}

	for _, tt := range cases {
		b.Run(tt.name, func(b *testing.B) {
			payload := make([]byte, tt.size)
			_, err := rand.Read(payload)
			require.NoError(b, err)

			b.SetBytes(int64(tt.size))
			b.ResetTimer()
			for range b.N {
				encoder.apply(payload)
			}
		})
	}
}
