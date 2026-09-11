//go:build go1.27 && goexperiment.simd && (amd64 || arm64)

package easyconnect

import (
	"simd"
)

func xorKey(buffer []byte, key byte) {
	keys := simd.BroadcastUint8s(key)
	width := keys.Len()
	for len(buffer) >= width {
		simd.LoadUint8s(buffer).Xor(keys).Store(buffer)
		buffer = buffer[width:]
	}
	if len(buffer) > 0 {
		tail, _ := simd.LoadUint8sPart(buffer)
		tail.Xor(keys).StorePart(buffer)
	}
}
