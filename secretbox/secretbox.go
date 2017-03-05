// Copyright (c) 2017 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// Package secretbox provides functions to encrypt and decrypt
// messages with a secret key.
//
// The Encrypt function of secretbox encrypts and authenticates the
// given msg with a provided msg id, context a secret root key.
// None of these must be unique. Furthermore secretbox tries to
// mitigate the implications of a bad RNG.
package secretbox

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"strconv"

	"github.com/aead/hydrogen/auth"
	"github.com/aead/hydrogen/internal/chacha20"
	"github.com/aead/hydrogen/subtle"
)

const (
	// HeaderSize is the overhead of the ciphertext in bytes.
	HeaderSize = 36
	// KeySize is the size of en/decryption key in bytes.
	KeySize = 32
)

var zero = [16]byte{}

// GenerateKey returns a random en/decryption key.
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

// Encrypt encrypts and authenticates msg and writes the result to ciphertext.
// The ciphertext must be at least 36 bytes longer than the msg, otherwise this
// function panics. The reader should return random data or can be nil - than the
// PRNG of the system will be used. The context must be 8 and the key 32 bytes long,
// otherwise this function panics.
func Encrypt(ciphertext, msg []byte, id uint64, rand io.Reader, context, key []byte) {
	if len(ciphertext) < len(msg)+HeaderSize {
		panic("hydrogen/secretbox: ciphertext is too small")
	}
	if k := len(key); k != KeySize {
		panic("hydrogen/secretbox: invalid key size " + strconv.Itoa(k))
	}
	if c := len(context); c != 8 {
		panic("hydrogen/secretbox: invalid context size " + strconv.Itoa(c))
	}
	if rand == nil {
		rand = crand.Reader // use global RNG
	}

	var t [64]byte
	var nonce [32]byte
	macKey, nonceKey, encKey := t[:16], t[16:32], t[32:]

	// macKey || nonceKey || encKey = ChaCha12(id||{0} , key)
	binary.LittleEndian.PutUint64(t[:], id)
	chacha20.Core(&t, t[:16], key)

	// tmp = SipHash(msg, context, nonceKey) ^ random_data
	// nonce = HChaCha12(zero , tmp)
	k := auth.Sum(msg, context, nonceKey)
	copy(nonce[:], k[:])
	rand.Read(nonce[16:]) // TODO(aead): Decide - fail if read fails or assume nothing about rand
	chacha20.HChaCha20(nonce[:], zero[:], nonce[:])
	copy(nonce[20:], zero[:4])

	// enc = XChaCha12(msg, nonce, encKey)
	// mac = SipHash(nonce||enc, context, macKey)
	// c   = nonce || mac || enc
	chacha20.XORKeyStream(ciphertext[HeaderSize:], msg, nonce[:24], encKey)
	copy(ciphertext, nonce[:20])

	hash := auth.New(context, macKey)
	hash.Write(ciphertext[:20])
	hash.Write(ciphertext[HeaderSize:])
	hash.Sum(ciphertext[20:20])
}

var errDecrypt = errors.New("hydrogen/secretbox: authentication failed")

// Decrypt decrypts a ciphertext encrypted with Encrypt and writes the result to msg.
// The msg can be 36 bytes shorter than the ciphertext. The context must be 8 and the
// key 32 bytes long, otherwise this function panics.
// This function returns a non-nil error if the ciphertext could not decrypted with
// the given id, context and key. In this case msg must not be used.
func Decrypt(msg, ciphertext []byte, id uint64, context, key []byte) (err error) {
	if c := len(ciphertext); c < HeaderSize {
		err = errDecrypt
		return
	}
	if len(msg) < len(ciphertext)-HeaderSize {
		panic("hydrogen/secretbox: msg buffer is to small")
	}
	if c := len(context); c != 8 {
		panic("hydrogen/secretbox: invalid context size " + strconv.Itoa(c))
	}

	var t [64]byte
	var nonce [24]byte
	macKey, encKey := t[:16], t[32:]

	// macKey || nonceKey || encKey = ChaCha12(id||{0} , key)
	binary.LittleEndian.PutUint64(t[:], id)
	chacha20.Core(&t, t[:16], key)

	// mac = SipHash(nonce||enc, context, macKey)
	var mac [auth.TagSize]byte
	hash := auth.New(context, macKey)
	hash.Write(ciphertext[:20])
	hash.Write(ciphertext[HeaderSize:])
	hash.Sum(mac[:0])

	if !subtle.Equal(ciphertext[20:HeaderSize], mac[:]) {
		err = errDecrypt
		return
	}

	// msg = XChaCha12(enc, nonce||{0}, encKey)
	copy(nonce[:], ciphertext[:20])
	chacha20.XORKeyStream(msg, ciphertext[HeaderSize:], nonce[:], encKey)
	return
}
