// Package icontest makes an image whose favicon hash is a chosen one, so a
// test can serve the icon of a product the detection templates list without
// shipping that product's image.
package icontest

import (
	"encoding/base64"
	"math/bits"
	"strconv"
)

const (
	c1, c2 = 0xcc9e2d51, 0x1b873593
	add    = 0xe6546b64
)

func inv(a uint32) uint32 { // a^-1 mod 2^32, a odd
	x := a
	for i := 0; i < 5; i++ {
		x *= 2 - a*x
	}
	return x
}

func mixK(k uint32) uint32 { return bits.RotateLeft32(k*c1, 15) * c2 }

func unmixK(k uint32) uint32 { return inv(c1) * bits.RotateLeft32(k*inv(c2), -15) }

func fmix(h uint32) uint32 {
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	return h ^ h>>16
}

func unxorshift(h uint32, s uint) uint32 { // inverse of h ^= h >> s
	x := h
	for i := s; i < 32; i += s {
		x = h ^ x>>s
	}
	return x
}

func unfmix(h uint32) uint32 {
	h = unxorshift(h, 16)
	h *= inv(0xc2b2ae35)
	h = unxorshift(h, 13)
	h *= inv(0x85ebca6b)
	return unxorshift(h, 16)
}

func step(h, k uint32) uint32 { return bits.RotateLeft32(h^mixK(k), 13)*5 + add }

func unstep(h, k uint32) uint32 { return bits.RotateLeft32((h-add)*inv(5), -13) ^ mixK(k) }

func word(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func hash(text []byte) uint32 {
	var h uint32
	n := len(text) / 4
	for i := 0; i < n; i++ {
		h = step(h, word(text[4*i:]))
	}
	if t := text[4*n:]; len(t) > 0 {
		var k uint32
		for i := len(t) - 1; i >= 0; i-- {
			k = k<<8 | uint32(t[i])
		}
		h ^= mixK(k)
	}
	return fmix(h ^ uint32(len(text)))
}

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func valid(b byte) bool {
	for i := 0; i < len(alphabet); i++ {
		if alphabet[i] == b {
			return true
		}
	}
	return false
}

// Body is a PNG-shaped image of 57 bytes whose favicon hash (the signed
// MurmurHash3 of its base64 text, as Shodan and the templates write it) is
// hash. It panics for a hash it cannot make or one that is not a number.
func Body(hash32 string) []byte {
	n, err := strconv.ParseInt(hash32, 10, 32)
	if err != nil {
		panic("icontest: " + err.Error())
	}
	target := uint32(int32(n))
	img := make([]byte, 57)
	copy(img, "\x89PNG\r\n\x1a\n")
	for i := 12; i < 57; i++ {
		img[i] = byte('a' + i%26)
	}
	for try := uint32(0); try < 1<<24; try++ {
		img[8], img[9], img[10] = byte(try), byte(try>>8), byte(try>>16)
		img[30], img[31], img[32] = 0, 0, 0
		text := []byte(base64.StdEncoding.EncodeToString(img) + "\n")
		// The state before the free block (text 40..43), forward.
		var hp uint32
		for i := 0; i < 10; i++ {
			hp = step(hp, word(text[4*i:]))
		}
		// The state after it, backward from the target: the tail "\n", the length and the last blocks are fixed.
		s := unfmix(target) ^ uint32(len(text))
		s ^= mixK(uint32(text[76]))
		for i := 18; i >= 11; i-- {
			s = unstep(s, word(text[4*i:]))
		}
		k := unmixK(bits.RotateLeft32((s-add)*inv(5), -13) ^ hp)
		blk := []byte{byte(k), byte(k >> 8), byte(k >> 16), byte(k >> 24)}
		ok := true
		for _, b := range blk {
			ok = ok && valid(b)
		}
		if !ok {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(string(blk))
		if err != nil {
			continue
		}
		copy(img[30:33], raw)
		if got := hash2(img); got == target {
			return img
		}
	}
	panic("icontest: no image for " + hash32)
}

func hash2(img []byte) uint32 {
	return hash([]byte(base64.StdEncoding.EncodeToString(img) + "\n"))
}
