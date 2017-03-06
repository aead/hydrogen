// Copyright (c) 2017 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package secretbox

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func fromHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestTolerance(t *testing.T) {
	context := []byte("libtests")
	key := fromHex("b634b3278d800dc126f589ef84d82ab04e0a11bc79c5181e195ddf8f376aad8d")
	badKey := make([]byte, len(key))
	msg := fromHex("e1047ba9476bf8ff312c01b4345a7d8ca5792b0ad467313f1d")
	msg2 := fromHex("e1047ba9476bf8ff312c01b4345a7d8ca5792b0ad467313f1d")
	ciphertext := make([]byte, len(msg)+HeaderSize)

	for i := range msg {
		Encrypt(ciphertext[:HeaderSize+i], msg[:i], uint64(i), nil, context, key)

		if Decrypt(msg2[:i], ciphertext[:HeaderSize+i], uint64(i), []byte("wrongctx"), key) == nil {
			t.Fatalf("%d: Decrypt accepted wrong context", i)
		}
		if Decrypt(msg2[:i], ciphertext[:HeaderSize+i], uint64(i+1), context, key) == nil {
			t.Fatalf("%d: Decrypt accepted wrong msg id", i)
		}

		copy(badKey, key)
		badKey[i%32]++
		if Decrypt(msg2[:i], ciphertext[:HeaderSize+i], uint64(i), context, badKey) == nil {
			t.Fatalf("%d: Decrypt accepted bad root key", i)
		}
		if Decrypt(msg2[:i], ciphertext[:HeaderSize+i], uint64(i), context, key) != nil {
			t.Fatalf("%d: Decrypt rejected correct ciphertext, msg_id, context and root key", i)
		}
		if !bytes.Equal(msg, msg2) {
			t.Fatalf("%d: Decrypt returned unexpected message", i)
		}
		key[i%32] += byte(i)
	}
}

func benchEncrypt(size int, b *testing.B) {
	key := make([]byte, KeySize)
	context := make([]byte, 8)
	msg := make([]byte, size)
	ciphertext := make([]byte, size+HeaderSize)

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(ciphertext, msg, 0, nil, context, key)
	}
}

func BenchmarkEncrypt64(b *testing.B)   { benchEncrypt(64, b) }
func BenchmarkEncrypt1024(b *testing.B) { benchEncrypt(1024, b) }

func benchDecrypt(size int, b *testing.B) {
	key := make([]byte, KeySize)
	context := make([]byte, 8)
	msg := make([]byte, size)
	ciphertext := make([]byte, size+HeaderSize)
	Encrypt(ciphertext, msg, 0, nil, context, key)

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(msg, ciphertext, 0, context, key)
	}
}

func BenchmarkDecrypt64(b *testing.B)   { benchEncrypt(64, b) }
func BenchmarkDecrypt1024(b *testing.B) { benchEncrypt(1024, b) }
