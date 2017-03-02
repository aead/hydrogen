// Copyright (c) 2017 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package chacha20

func xorKeyStream(dst, src []byte, block, state *[64]byte) int {
	return xorKeyStreamGeneric(dst, src, block, state)
}

func hChaCha20(dst, nonce, key []byte) {
	hChaCha20Generic(dst, nonce, key)
}
