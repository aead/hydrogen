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
	SipHash_2_4
)

var (
	errUnknownAlgorithm = errors.New("libsodium/hash: unknown algorithm")
)

type Algorithm uint

func Sum(alg Algorithm, key []byte) ([]byte, error) {
	var h hash.Hash
	var err error

	switch alg {
	default:
		err = errUnknownAlgorithm
	case BLAKE2b_512:
		h, err = blake2b.New512(key)
	case BLAKE2b_384:
		h, err = blake2b.New512(key)
	case BLAKE2b_256:
		h, err = blake2b.New512(key)
	}

	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func New(alg Algorithm, key []byte) (hash.Hash, error) {
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
