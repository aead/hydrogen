// Copyright (c) 2017 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// Package chacha20 implements the ChaCha20/12 and XChaCha20/12
// stream ciphers.
package chacha20

import "strconv"

const (
	// KeySize is the size of the key in bytes.
	KeySize = 32

	// NonceSize is the size of the ChaCha20 nonce in bytes.
	NonceSize = 12

	// XNonceSize is the size of the XChaCha20 nonce in bytes.
	XNonceSize = 24
)

var sigma = []byte{
	0x65, 0x78, 0x70, 0x61,
	0x6e, 0x64, 0x20, 0x33,
	0x32, 0x2d, 0x62, 0x79,
	0x74, 0x65, 0x20, 0x6b,
}

// XORKeyStream crypts bytes from src to dst using the given nonce and key.
// The length of the nonce determinds the version of ChaCha20:
// - 12 bytes: ChaCha20/12
// - 24 bytes: XChaCha20/12
// If the nonce is neither 12 nor 24 bytes long, this function panics.
// Src and dst may be the same slice but otherwise should not overlap.
// If len(dst) < len(src) this function panics.
func XORKeyStream(dst, src, nonce, key []byte) {
	if k := len(key); k != KeySize {
		panic("hydrogen/internal/chacha20: invalid key size " + strconv.Itoa(k))
	}
	var block, state [64]byte
	switch n := len(nonce); n {
	default:
		panic("hydrogen/internal/chacha20: invalid nonce size " + strconv.Itoa(n))
	case NonceSize:
		copy(state[:16], sigma[:])
		copy(state[16:48], key)
		copy(state[52:], nonce)
	case XNonceSize:
		copy(state[:16], sigma[:])
		hChaCha20(state[16:48], nonce[:16], key)
		copy(state[56:], nonce[16:])
	}
	xorKeyStream(dst, src, &block, &state)
}

// NewCipher returns a chacha20.Cipher implementing either ChaCha20/12
// or XChaCha20/12 depending on the length of the nonce:
// - 12 bytes: ChaCha20/12
// - 24 bytes: XChaCha20/12
// If the nonce is neither 12 nor 24 bytes long, this function panics.
func NewCipher(nonce, key []byte) *Cipher {
	if k := len(key); k != KeySize {
		panic("hydrogen/internal/chacha20: invalid key size " + strconv.Itoa(k))
	}

	switch n := len(nonce); n {
	default:
		panic("hydrogen/internal/chacha20: invalid nonce size " + strconv.Itoa(n))
	case NonceSize:
		c := &Cipher{noncesize: NonceSize}
		copy(c.state[:16], sigma[:])
		copy(c.state[16:48], key)
		copy(c.state[52:], nonce)
		return c
	case XNonceSize:
		c := &Cipher{noncesize: XNonceSize}
		copy(c.state[:16], sigma[:])
		hChaCha20(c.state[16:48], nonce[:16], key)
		copy(c.state[56:], nonce[16:])
		return c
	}
}

// Cipher represents either a ChaCha20/12 or XChaCha20/12 stream cipher.
type Cipher struct {
	state, block [64]byte
	off          int
	noncesize    int
}

// XORKeyStream XORs each byte in the given slice with a byte from the
// cipher's key stream. Dst and src may point to the same memory.
// If len(dst) < len(src), XORKeyStream should panic. It is acceptable
// to pass a dst bigger than src, and in that case, XORKeyStream will
// only update dst[:len(src)] and will not touch the rest of dst.
func (c *Cipher) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("hydrogen/internal/chacha20: dst buffer is to small")
	}

	if c.off > 0 {
		n := len(c.block[c.off:])
		if len(src) <= n {
			for i, v := range src {
				dst[i] = v ^ c.block[c.off]
				c.off++
			}
			if c.off == 64 {
				c.off = 0
			}
			return
		}

		for i, v := range c.block[c.off:] {
			dst[i] = src[i] ^ v
		}
		src = src[n:]
		dst = dst[n:]
		c.off = 0
	}

	c.off += xorKeyStream(dst, src, &(c.block), &(c.state))
}

// HChaCha20 computes HChaCha20/12 using the given key-nonce
// combination and writes the result to dst. Therefore key must be
// 32 and nonce must be 16 bytes long. If len(dst) < 32 this function
// panics. It is acceptable to pass a dst longer than 32 bytes, and in
// that case, HChaCha20 will only update dst[:32] and will not touch
// the rest of dst.
func HChaCha20(dst []byte, nonce []byte, key []byte) {
	if len(dst) < 32 {
		panic("hydrogen/internal/chacha20: dst is smaller than 32 bytes")
	}
	if n := len(nonce); n != 16 {
		panic("hydrogen/internal/chacha20: invalid nonce size " + strconv.Itoa(n))
	}
	if k := len(key); k != KeySize {
		panic("hydrogen/internal/chacha20: invalid key size " + strconv.Itoa(k))
	}
	hChaCha20(dst, nonce, key)
}
