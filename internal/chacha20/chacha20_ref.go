// Copyright (c) 2017 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package chacha20

func core(dst *[64]byte, nonce []byte, key []byte) {
	var state [64]byte
	copy(state[:16], sigma[:])
	copy(state[16:48], key[:])
	copy(state[48:], nonce[:])
	chacha20Generic(dst, &state)
}

func xorKeyStream(dst, src []byte, block, state *[64]byte) int {
	return xorKeyStreamGeneric(dst, src, block, state)
}

func hChaCha20(dst, nonce, key []byte) {
	hChaCha20Generic(dst, nonce, key)
}
