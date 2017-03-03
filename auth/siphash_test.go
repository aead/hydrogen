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
	for i, v := range vectors {
		msg[i] = byte(i)

		tag := Sum(msg, context, key)
		if !bytes.Equal(tag[:], fromHex(v)) {
			t.Errorf("Failed at %d:\ngot:  %s\nwant: %s", i, hex.EncodeToString(tag[:]), v)
		}
	}
}

var vectors = []string{
	"f896e134f1a0c57e3caa11d37b48b5f3", "6df99f0e43e07c965c8b0f73d2ac9cd9", "ed001efc0e97d65b029bc997ef5f583b", "345e55d3a5b85574f38ee7b2662eb2eb",
	"6a6e245fda79d718f22e2cbe8d4556fd", "4850fc430a8055b96403324f4071b076", "99035dee17cdcddb9da4e5d9c5152ab2", "2477c9803dcbb6a86c4712374b205d9e",
	"916a038d182135002cdee0a61d2cb4b0", "62decae7c1e724dda73336e9956d2c4d", "c7c923bdbeb69074d918b7ed31b03dc2", "af95b43e7e939e1c5d55797a34d9343d",
	"cbb9fb310be777185e562b6b2b9a7548", "2baf051709deaebf4fcb387625ad8af4", "3a056cc5c9f18f31b00dc9d14766594c", "9bcfe38d12cfbfce83f4029458484961",
	"6e563359b4f674834aceeb80dd2eca04", "c8a4cd6594f79b3df6bf1426d5ffdb96", "751289b7ae385295309d62ae0ae7e9b2", "e56732e9505db8ab6823a2fcf6073f18",
	"ff793ba05b33ad2b40a28eed9bc5c9cc", "be07061fedca56082de9042a0ca18efe", "726d65f0eb9eb73999b316b3403e8551", "7b7f1cb11a1d589054f96ded6780b385",
	"c8614e59fb9d2f45d920b0e31ff70ba9", "97f7c865af57c4064532e5f3e47d0ee3", "fc6eed3abb33870978e01925931c2c77", "68517491cc1c0159039adef40e4a5884",
	"53f59cf2da263c41e11e4431f21ba975", "a042397d1177281ecfdeb94c7dada4b8", "2030770f95d4b08e6fe059158bfaaa80", "b8a4242bb9ecf78a30fbe1229a1cafca",
	"5e25dafd501eafde576bf1556bfa8c7b", "35310328ee7312987b1438f00cbd732b", "56379aa5f4ec19e52e1cbedb6cd54cf4", "b5d6db8d32c0614f87205cdeb43ec151",
	"303ae259d78a95b82a46cea9ca78d478", "d293b47452d4aab18cc01e80e63929bc", "808cceaa44a6d89eac19cca7f4f2a9a9", "a77c20c1fdc5db759e03f7394b10762e",
	"98c96bb66c170d184f394765decc87b8", "2308d737a6f27aeb18d76276223c4908", "91129370532baedb45aa01a72c517c77", "cd74314bb04228f71dd546e352ed19d6",
	"b2a422f69dab7b80f9c79f3601d27f5f", "658a50433acdea6f9c46888e2e4964cd", "ea2c33e0b9f1a241d4b90d2dc684e609", "068ea33c5d4fb4935ecc5bebd8a93d48",
	"d58e48c555dbadc09bff32223512398f", "07b69429bf3e7db8ac65a1099feeaa5f", "17a0607f65a4c6257d9f321a5bf7b4f2", "5f404445854ddab9c463f35fadc2cff8",
	"613bee96449b8c0cd52c2253a6635841", "c3fa9171de16beaf68ccffd49c1d10bb", "fa7fd667a792c36633a46556b19c324f", "dba0acbe3d5a0ad6b3e7a731820b153d",
	"91be4de60f5ba40ea02cbefd2072a1f9", "cd0b02ef791b0e206c38ae90109a561e", "80d0ca00aab2b1bdab63fc5237c908f1", "95f82495193d28373f5f661d6284a641",
	"1f622a4201c740db47dbc1b244c2afc8", "8b2de6c0ac314ddba29d49eb58c2a31d", "6e04979c2cf8f5bc7616b35da54f089c", "17c193f5ffa3e315c2a744f32b7b779c",
}
