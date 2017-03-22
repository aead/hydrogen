// Copyright (c) 2017 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// Package auth provides functions to quickly compute and verify
// 128 bit authentication tags for arbitrary long messages.
//
// Therefore this package uses SipHash-128 with c=2 and d=4.
package auth

import (
	"encoding/binary"
	"hash"
	"io"
	"strconv"

	"github.com/aead/hydrogen/subtle"
)

const (
	// TagSize is the size of a SipHash-128 authentication tag in bytes.
	TagSize = 16
	// KeySize is the size of a SipHash-128 key in bytes.
	KeySize = 16
	// BlockSize is the blocksize of SipHash-128 in bytes.
	BlockSize = 8
)

const (
	c0 = 0x736f6d6570736575
	c1 = 0x646f72616e646f6d ^ 0xee
	c2 = 0x6c7967656e657261
	c3 = 0x7465646279746573
)

// GenerateKey returns a random SipHash-128 key.
// Therefore the given reader must return random data.
// This function returns a non-nil error if the given reader
// fails to provide enough data. In this case the returned
// key is nil must not used.
func GenerateKey(rand io.Reader) (key []byte, err error) {
	key = make([]byte, KeySize)
	_, err = io.ReadFull(rand, key)
	if err != nil {
		key = nil
	}
	return
}

// Sum returns an authentication tag of the given msg using the provided
// context and key. The context must be 8 and the key must be 16 bytes long.
// Otherwise this function panics.
func Sum(msg, context, key []byte) [TagSize]byte {
	if k := len(key); k != KeySize {
		panic("hydrogen/auth: invalid key size " + strconv.Itoa(k))
	}
	if c := len(context); c != 8 {
		panic("hydrogen/auth: invalid context size " + strconv.Itoa(c))
	}
	var tag [TagSize]byte

	h := New(context, key)
	h.Write(msg)
	h.Sum(tag[:0])

	return tag
}

// Verify returns true if and only if tag is a valid authenticator for
// msg with the given context and key. The context must be 8 and the key
// must be 16 bytes long. Otherwise this function panics.
func Verify(tag [TagSize]byte, msg, context, key []byte) bool {
	checksum := Sum(msg, context, key)
	return subtle.Equal(tag[:], checksum[:])
}

// New returns a new hash.Hash computing the SipHash-128 authentication tag
// with the given context and key. The context must be 8 and the key must
// be 16 bytes long. Otherwise this function panics.
func New(context, key []byte) hash.Hash {
	if k := len(key); k != KeySize {
		panic("hydrogen/auth: invalid key size " + strconv.Itoa(k))
	}
	if c := len(context); c != 8 {
		panic("hydrogen/auth: invalid context size " + strconv.Itoa(c))
	}
	k0 := binary.LittleEndian.Uint64(key)
	k1 := binary.LittleEndian.Uint64(key[8:])

	d := new(digest)
	d.iVal[0] = k0 ^ c0
	d.iVal[1] = k1 ^ c1
	d.iVal[2] = k0 ^ c2
	d.iVal[3] = k1 ^ c3
	siphashCore(&(d.iVal), context)

	d.Reset()
	return d
}

type digest struct {
	hVal, iVal [4]uint64
	buf        [BlockSize]byte
	off        int
	ctr        byte
}

func (d *digest) Size() int { return TagSize }

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Reset() {
	d.hVal = d.iVal
	d.off = 0
	d.ctr = 0
}

func (d *digest) Write(p []byte) (n int, err error) {
	n = len(p)
	d.ctr += byte(n)

	if d.off > 0 {
		dif := BlockSize - d.off
		if n < dif {
			d.off += copy(d.buf[d.off:], p)
			return
		}
		copy(d.buf[d.off:], p[:dif])
		siphashCore(&(d.hVal), d.buf[:])
		p = p[dif:]
		d.off = 0
	}
	if nn := len(p) &^ (BlockSize - 1); nn >= BlockSize {
		siphashCore(&(d.hVal), p[:nn])
		p = p[nn:]
	}
	if len(p) > 0 {
		d.off = copy(d.buf[:], p)
	}
	return n, nil
}

func (d *digest) Sum(sum []byte) []byte {
	var tag [TagSize]byte
	hVal := d.hVal
	buf := d.buf
	for i := d.off; i < BlockSize-1; i++ {
		buf[i] = 0
	}
	buf[7] = d.ctr
	siphashFinalize(&tag, &hVal, &buf)
	return append(sum, tag[:]...)
}
