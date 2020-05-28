// Copyright (C) 2020 GateChain.
// This file is part of gatechain/crypto(dev@gatechain.org).
//
// crypto is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// crypto is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with crypto.  If not, see <https://www.gnu.org/licenses/>.

package bytes

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// This is a trivial test for protobuf compatibility.
func TestMarshal(t *testing.T) {
	bz := []byte("hello world")
	dataB := HexBytes(bz)
	bz2, err := dataB.Marshal()
	assert.Nil(t, err)
	assert.Equal(t, bz, bz2)

	var dataB2 HexBytes
	err = (&dataB2).Unmarshal(bz)
	assert.Nil(t, err)
	assert.Equal(t, dataB, dataB2)
}

// Test that the hex encoding works.
func TestJSONMarshal(t *testing.T) {

	type TestStruct struct {
		B1 []byte
		B2 HexBytes
	}

	cases := []struct {
		input    []byte
		expected string
	}{
		{[]byte(``), `{"B1":"","B2":""}`},
		{[]byte(`a`), `{"B1":"YQ==","B2":"61"}`},
		{[]byte(`abc`), `{"B1":"YWJj","B2":"616263"}`},
	}

	for i, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("Case %d", i), func(t *testing.T) {
			ts := TestStruct{B1: tc.input, B2: tc.input}

			// Test that it marshals correctly to JSON.
			jsonBytes, err := json.Marshal(ts)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, string(jsonBytes), tc.expected)

			// Test that unmarshaling works correctly.
			ts2 := TestStruct{}
			err = json.Unmarshal(jsonBytes, &ts2)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, ts2.B1, tc.input)
			assert.Equal(t, ts2.B2, HexBytes(tc.input))
		})
	}
}
