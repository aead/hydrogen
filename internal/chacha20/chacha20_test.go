// Copyright (c) 2017 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package chacha20

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

func TestVectors(t *testing.T) {
	for i, v := range vectors {
		key := fromHex(v.key)
		nonce := fromHex(v.nonce)
		keystream := fromHex(v.keystream)
		dst := make([]byte, len(keystream))

		XORKeyStream(dst, dst, nonce, key)
		if !bytes.Equal(dst, keystream) {
			t.Errorf("%d:\ngot:  %s\nwant: %s", i, hex.EncodeToString(dst), hex.EncodeToString(keystream))
		}
	}
}

var vectors = []struct {
	key, nonce, keystream string
}{
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		"9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f0564f879d27ae3c02ce82834acfa8c793a629f2ca0de6919610be82f411326be0bd58841203e74fe86fc71338ce0173dc628ebb719bdcbcc151585214cc089b442258dcda14cf111c602b8971b8cc843e91e46ca905151c02744a6b017e69316b20cd67c4bdecc538e8be990c1b6425d68bfd3a6fe97693e4846351596cca8abf59fddd0b7f52dcc0c60a448cbf9511610b0a742f1e4d238a7a45cae054ec2",
	},
	{
		"8000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		"789cc357f0b6cda5395f08c8538f1226d08eb3e16ebd6b6db6cc9ca77d81d900bb9d21f6ef0b720550d161f1a80fab0468e48c086daad356edce3a3f988d8e",
	},
	{
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"000000000001020304050607",
		"6898eb04f3d151985e28e882f35daf28d2a1689f79081ffb08cdc48edbbd3dcd683c764f3dd7302293928ca3d4ef4194e6e22f41a72204a14b89115d06ca29fb0b9f6eba3da6793a928afe76cdf62a5d5b0898bb9bb2348612189fdb825e5aa7559c9ec79ff80d05079fad81e9bc2521b2ebcb179cebeade91f20ff3e13192d60de2ee983ec07047e7827594773c28448d89e9b96bb0f8665b1a56f85abebd584a446e17d5a6fb847a1dbf341ece5124ff5f80d4a57fb7edf65a2907939b2f3c9654ccbfa2e5225edc8d799bf7ce296d6c8f9234cec0bd7b91b3d2ddc27f93ff8591ddb362b54fab111a7da9d5b4187661ed0e691f7aa5959fb83112427a95bbeb",
	},
}

func BenchmarkCore(b *testing.B) {
	var dst [64]byte
	key := make([]byte, KeySize)
	nonce := make([]byte, 16)

	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Core(&dst, nonce, key)
	}
}

func BenchmarkHChaCha12(b *testing.B) {
	dst := make([]byte, 32)
	key := make([]byte, KeySize)
	nonce := make([]byte, 16)

	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HChaCha20(dst[:], nonce, key)
	}
}

func benchXORKeyStream(size, nsize int, b *testing.B) {
	key := make([]byte, KeySize)
	nonce := make([]byte, nsize)
	buf := make([]byte, size)

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		XORKeyStream(buf, buf, nonce, key)
	}
}

func BenchmarkChaCha12_64(b *testing.B)    { benchXORKeyStream(64, NonceSize, b) }
func BenchmarkChaCha12_1024(b *testing.B)  { benchXORKeyStream(1024, NonceSize, b) }
func BenchmarkXChaCha12_64(b *testing.B)   { benchXORKeyStream(64, XNonceSize, b) }
func BenchmarkXChaCha12_1024(b *testing.B) { benchXORKeyStream(1024, XNonceSize, b) }
