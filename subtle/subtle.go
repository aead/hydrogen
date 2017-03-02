// Copyright (c) 2017 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// Package subtle implements some functions that are often useful
// in cryptographic code. All functions in subtle take constant time.
package subtle

import csubtle "crypto/subtle"

// Equal returns true if and only if the two slices, x
// and y, have equal contents.
func Equal(x, y []byte) bool {
	return csubtle.ConstantTimeCompare(x, y) == 1
}

// Increment increments the slice val encoded as little
// endian number.
func Increment(val []byte) {
	t := uint16(1)
	for i := range val {
		t += uint16(val[i])
		val[i] = byte(t)
		t >>= 8
	}
}
