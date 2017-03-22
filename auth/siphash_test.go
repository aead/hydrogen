// Copyright (c) 2017 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package auth

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
	context := []byte("libtests")
	key := fromHex("000102030405060708090a0b0c0d0e0f")
	msg := make([]byte, 64)
	h := New(context, key)
	for i, v := range vectors {
		msg[i] = byte(i)

		h.Write(msg[:i])
		sum := h.Sum(nil)
		if !bytes.Equal(sum, fromHex(v)) {
			t.Fatalf("%d (single write): got:  %s - want: %s", i, hex.EncodeToString(sum), v)
		}
		h.Reset()

		for j := 0; j < i; j++ {
			h.Write(msg[j : j+1])
		}
		sum = h.Sum(nil)
		if !bytes.Equal(sum, fromHex(v)) {
			t.Fatalf("%d (multi write): got:  %s - want: %s", i, hex.EncodeToString(sum), v)
		}
		h.Reset()

		tag := Sum(msg[:i], context, key)
		if !bytes.Equal(tag[:], fromHex(v)) {
			t.Fatalf("%d (sum): got:  %s - want: %s", i, hex.EncodeToString(tag[:]), v)
		}
	}
}

var vectors = []string{
	"f007303cdc342cbcc97f50ac927fbd18", "63eaa3aa546391b8f9970812754febd0", "0e2de8341a79d492e8a5a91ed6664eb7", "9d284cd00663c66564489945b353127a",
	"71d4f0d2def6e3c475f0d97ce47cff3f", "d177f628fdd3d7677acde18e511f6aa9", "69dbb986e9b4d972d4a2c574915e07f1", "c6a354e08593e02a3f510c2120f0be0b",
	"323dbece090349e8b3c40a6d27b94d16", "5b5d046aebd78324129b6f860fd11342", "eed90dafb8909fa86b18ff866bb0a17b", "aa1398a834becc3a8dc13c6b776e73b7",
	"28bd80e78bafb9c473e52c0352bf9fc3", "4c3d644f514465b0ee337f8ebb224909", "17c0d9326491f50b7a9c3a3408539e2f", "2b5cb3b89182bd6ba223aca5d9eca070",
	"954c1bdb736d683cc14e2b7c9b8a149f", "3a1813a77f8712adee7fc06be8b0c79f", "d3b2dd766512023d3948a5dff330a34c", "b13c74b68aaad20433c88c0ffbc104ce",
	"aed0d7c0b6911d3e41fae4db1401af4e", "48d6d6d63aba9615c5560ca7bc7815e0", "7d1ddc6fa6777328e0a2a2503f4b5c76", "fb37612e2c6d704c2d7aeff2f8b631e4",
	"a9ef07eecc60fd1270a67049f3871299", "0c356ce6fd8b80fda2e53d33c86e1f32", "7b24d10fcf330b28c64c4e4a493bd0d5", "89aecacd06ceeb42523c27ea7e87aa67",
	"97694e5b647816d397d661e97969b853", "db0908df19cf60e174db082024e6f86a", "feffa391a5f4d19ffd6d47b5e409a9e1", "46a87f9493d5d559be74fded01245b50",
	"6298c18874e2f1c2fff26dee4be5f517", "2607506329d0473aa0633665bd3959bd", "30821af9db4f7c6b93847ae2e6ae24ba", "61e4c68f48aa5a597044b800fc7dfa22",
	"35d8b473e42ee9ba62ccc3efe7e5faa0", "d11a5779457bc74eb1ee761cd9457abe", "e42ec3a5f8b1119a0cca7ea3f7986e71", "52c658df09fc4c82fe916a18271ab3a7",
	"a3e9d605c7021b31e4300adc8e71642a", "a2d8db12b7cbc100f066e3ef6b347d26", "f3c43ca49c69d92325732eabc571dc11", "361ed4e7caeb1e3c823ffea0abbde84d",
	"be15bc07b765b6a3f6b225a33c622fd0", "4eace2d98f7f9489e65f6cef64d3ef88", "2dc35561bb2fcff3f926fcb7914082fd", "2914afd25859eaaf4990b14b7f4f6e44",
	"539f4b40858d9f73821a1d0e436e7015", "c3ab67641dc5dcae2880557fb1b6a201", "380b69a63523f3ac6de5a4bae8e766e7", "9072651cd86de6eff318abff5a7b580e",
	"a9418ccb168e5105894319f638269c4b", "7eb52c4528dce4dac667b63bb1b5e88b", "79b773cf3719986ed3ff912235c0e726", "0a57ae44eace6962ddcca46b4c739e80",
	"7eaa28101d30517d2361ca2dae15c090", "f3bc3ebc008c55b57f970f94006f6a9f", "0a5f93ee7110a36907cf40fe2c7f53df", "cec8f9c25c24847b9ece8994cc8189bb",
	"e54ded96d7f52a68212bdecf804261d0", "46f1655d1611932cd0795a888fabd2a5", "adf2f6000077ddebd240f9797bbf8f57", "0013765ea34785ef1ffeebe345a2a66a",
}

func benchWrite(size int, b *testing.B) {
	key := make([]byte, KeySize)
	context := []byte("runbench")
	msg := make([]byte, size)

	h := New(context, key)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(msg)
	}
}

func BenchmarkWrite8(b *testing.B)  { benchWrite(8, b) }
func BenchmarkWrite64(b *testing.B) { benchWrite(64, b) }
func BenchmarkWrite1K(b *testing.B) { benchWrite(1024, b) }

func benchSum(size int, b *testing.B) {
	key := make([]byte, KeySize)
	context := []byte("runbench")
	msg := make([]byte, size)

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum(msg, context, key)
	}
}

func BenchmarkSum8(b *testing.B)  { benchSum(8, b) }
func BenchmarkSum64(b *testing.B) { benchSum(64, b) }
func BenchmarkSum1K(b *testing.B) { benchSum(1024, b) }
