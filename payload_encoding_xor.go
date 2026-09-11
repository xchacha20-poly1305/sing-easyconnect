//go:build !go1.27 || !goexperiment.simd || (!amd64 && !arm64)

package easyconnect

func xorKey(buffer []byte, key byte) {
	for i := range buffer {
		buffer[i] ^= key
	}
}
