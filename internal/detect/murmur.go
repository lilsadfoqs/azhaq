package detect

import (
	"math/bits"
	"strconv"
)

// Mmh3String is the signed 32-bit MurmurHash3 (seed 0) of s as a decimal
// string, the form template favicon hashes are written in.
func Mmh3String(s string) string {
	return strconv.Itoa(int(int32(murmur3(s))))
}

// murmur3 is MurmurHash3 x86 32-bit, as in internal/fingerprint.
func murmur3(data string) uint32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	var h uint32
	n := len(data) / 4
	for i := 0; i < n; i++ {
		j := i * 4
		k := uint32(data[j]) | uint32(data[j+1])<<8 | uint32(data[j+2])<<16 | uint32(data[j+3])<<24
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}
	var k uint32
	switch tail := data[n*4:]; len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}
