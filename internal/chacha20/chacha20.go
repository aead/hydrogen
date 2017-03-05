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
	if len(dst) < len(src) {
		panic("hydrogen/internal/chacha20: dst buffer is to small")
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

// Core generates 64 bytes of ChaCha20/12 keystream using the given
// key-nonce combination and writes the result to dst. Therefore key
// must be 32 and nonce must be 16 bytes long.
func Core(dst *[64]byte, nonce []byte, key []byte) {
	if k := len(key); k != KeySize {
		panic("hydrogen/internal/chacha20: invalid key size " + strconv.Itoa(k))
	}
	if n := len(nonce); n != 16 {
		panic("hydrogen/internal/chacha20: invalid nonce size " + strconv.Itoa(n))
	}
	core(dst, nonce, key)
}
