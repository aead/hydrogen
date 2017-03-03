// Copyright (c) 2017 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package auth

func siphashCore(hVal *[4]uint64, msg []byte) {
	siphashCoreGeneric(hVal, msg)
}

func siphashFinalize(tag *[TagSize]byte, hVal *[4]uint64, buf *[8]byte) {
	siphashFinalizeGeneric(tag, hVal, buf)
}
