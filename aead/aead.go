// Copyright (c) 2017 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package aead

import (
	"crypto/cipher"
	"errors"

	"github.com/aead/chacha20poly1305"
)

const TagSize = 16

const (
	ChaCha20Poly1305 Algorithm = 1 + iota
	ChaCha20Poly1305_IETF
	XChaCha20Poly1305
	unknown
)

var (
	errUnknownAlgorithm = errors.New("libsodium/aead: unknown algorithm")
	errInvalidKeySize   = errors.New("libsodium/aead: bad key length")
)

type Algorithm uint

func (alg Algorithm) isKnown() bool {
	return alg > 0 && alg < unknown
}

func (alg Algorithm) newCipher(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errInvalidKeySize
	}
	if !alg.isKnown() {
		return nil, errUnknownAlgorithm
	}

	switch alg {
	default:
		return chacha20poly1305.NewCipher(key)
	case ChaCha20Poly1305_IETF:
		return chacha20poly1305.NewIETFCipher(key)
	case XChaCha20Poly1305:
		return chacha20poly1305.NewXCipher(key)
	}
}

// Encrypt encrypts and authenticates the plaintext and writes the result to ciphertext.
// The authentication tag is appended to the ciphertext - therefore the ciphertext must be
// 16 bytes longer than the plaintext. The additionalData is not encrypted but authenticated
// and can be nil.
// The nonce must be unique for one specific key and should either be randomly genereated every
// time or genereated randomly once and incremented continuously (like a counter) - depending
// on the size of the nonce. See the nonce generation guidelines for details.
// A non-nil error indicates, that the encryption operation failed.
func (alg Algorithm) Encrypt(ciphertext, plaintext, additionalData, nonce, key []byte) (err error) {
	c, err := alg.newCipher(key)
	if err != nil {
		return
	}
	c.Seal(ciphertext[:0], nonce, plaintext, additionalData)
	return
}

// Decrypt decrypts and checks integrity of the ciphertext and writes the result to plaintext.
// This function is the inverse operation of Encrypt.
// A non-nil error indicates, that the encryption operation failed - especially modifed ciphertext
// or additionalData leads to different authentication tag and causes this function to fail with additionalData
// non-nil error.
func (alg Algorithm) Decrypt(plaintext, ciphertext, additionalData, nonce, key []byte) (err error) {
	c, err := alg.newCipher(key)
	if err != nil {
		return
	}
	_, err = c.Open(plaintext[:0], nonce, ciphertext, additionalData)
	return
}
