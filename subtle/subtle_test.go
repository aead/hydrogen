// Copyright (c) 2017 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package subtle

import (
	"bytes"
	"testing"
)

var equalTest = []struct {
	x, y   []byte
	result bool
}{
	{nil, nil, true},
	{nil, []byte{}, true},
	{[]byte{0x00}, []byte{}, false},
	{[]byte{0x00}, []byte{0x01}, false},
	{[]byte{0x00, 0x01}, []byte{0x00, 0x01}, true},
	{[]byte{0x01, 0x00}, []byte{0x02, 0x00}, false},
	{[]byte{0x01, 0x00}, []byte{0x01}, false},
}

func TestEqual(t *testing.T) {
	for i, v := range equalTest {
		if r := Equal(v.x, v.y); r != v.result {
			t.Errorf("%d: got %v expected %v", i, r, v.result)
		}
	}
}

var incrementTest = []struct {
	val, result []byte
}{
	{nil, nil},
	{[]byte{0x00}, []byte{0x01}},
	{[]byte{0x2F}, []byte{0x30}},
	{[]byte{0xff}, []byte{0x00}},
	{[]byte{0x00, 0x00}, []byte{0x01, 0x00}},
	{[]byte{0xff, 0x00}, []byte{0x00, 0x01}},
	{[]byte{0xff, 0x0f}, []byte{0x00, 0x10}},
	{[]byte{0xff, 0xf0}, []byte{0x00, 0xf1}},
	{[]byte{0xff, 0xff, 0x00}, []byte{0x00, 0x00, 0x01}},
}

func TestIncrement(t *testing.T) {
	for i, v := range incrementTest {
		Increment(v.val)
		if !bytes.Equal(v.val, v.result) {
			t.Errorf("%d: got %v expected %v", i, v.val, v.result)
		}
	}
}

func benchEqual(size int, b *testing.B) {
	x, y := make([]byte, size), make([]byte, size)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Equal(x, y)
	}
}

func BenchmarkEqual_1(b *testing.B)    { benchEqual(1, b) }
func BenchmarkEqual_10(b *testing.B)   { benchEqual(10, b) }
func BenchmarkEqual_100(b *testing.B)  { benchEqual(100, b) }
func BenchmarkEqual_1K(b *testing.B)   { benchEqual(1024, b) }
func BenchmarkEqual_10K(b *testing.B)  { benchEqual(10*1024, b) }
func BenchmarkEqual_100K(b *testing.B) { benchEqual(100*1024, b) }

func benchIncrement(size int, b *testing.B) {
	val := make([]byte, size)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Increment(val)
	}
}

func BenchmarkIncrement_1(b *testing.B)    { benchIncrement(1, b) }
func BenchmarkIncrement_10(b *testing.B)   { benchIncrement(10, b) }
func BenchmarkIncrement_100(b *testing.B)  { benchIncrement(100, b) }
func BenchmarkIncrement_1K(b *testing.B)   { benchIncrement(1024, b) }
func BenchmarkIncrement_10K(b *testing.B)  { benchIncrement(10*1024, b) }
func BenchmarkIncrement_100K(b *testing.B) { benchIncrement(100*1024, b) }
