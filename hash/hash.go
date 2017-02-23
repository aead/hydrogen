// Copyright (c) 2017 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package hash

import (
	"errors"
	"hash"

	"golang.org/x/crypto/blake2b"
)

const (
	BLAKE2b_512 Algorithm = 1 + iota
	BLAKE2b_384
	BLAKE2b_256
)

var errUnknownAlgorithm = errors.New("libsodium/hash: unknown algorithm")

// Algorithm identifies a cryptographic hash function.
type Algorithm uint

// Sum returns the cryptographic hash value of msg. If the
// key is not nil, this function returns the MAC of msg.
func (alg Algorithm) Sum(msg, key []byte) ([]byte, error) {
	h, err := alg.New(key)
	if err != nil {
		return nil, error
	}
	h.Write(msg)
	return h.Sum(nil)
}

// New returns a hash.Hash computing a cryptographic hash (or MAC if key != nil)..
func (alg Algorithm) New(key []byte) (hash.Hash, error) {
	switch alg {
	default:
		return nil, errUnknownAlgorithm
	case BLAKE2b_512:
		return blake2b.New512(key)
	case BLAKE2b_384:
		return blake2b.New512(key)
	case BLAKE2b_256:
		return blake2b.New512(key)
	}
}
