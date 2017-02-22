// Copyright (c) 2017 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"github.com/aead/chacha20poly1305"
)

const (
	AES_GCM Algorithm = 1 + iota
	ChaCha20Poly1305
	ChaCha20Poly1305_IETF
	XChaCha20Poly1305
)

var (
	errUnknownAlgorithm = errors.New("libsodium/aead: unknown algorithm")
	errInvalidKeySize   = errors.New("libsodium/aead: bad key length")
)

type Algorithm uint

func NewCipher(alg Algorithm, key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errInvalidKeySize
	}

	switch alg {
	default:
		return nil, errUnknownAlgorithm
	case AES_GCM:
		c, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(c)
	case ChaCha20Poly1305:
		return chacha20poly1305.NewCipher(key)
	case ChaCha20Poly1305_IETF:
		return chacha20poly1305.NewIETFCipher(key)
	case XChaCha20Poly1305:
		return chacha20poly1305.NewXCipher(key)
	}
}

func Encrypt(alg Algorithm, dst, src, additionalData, nonce, key []byte) ([]byte, error) {
	c, err := NewCipher(alg, key)
	if err != nil {
		return nil, err
	}
	return c.Seal(dst[:0], nonce, src, additionalData), nil
}

func Decrypt(alg Algorithm, dst, src, additionalData, nonce, key []byte) ([]byte, error) {
	c, err := NewCipher(alg, key)
	if err != nil {
		return nil, err
	}
	return c.Open(dst[:0], nonce, src, additionalData)
}
