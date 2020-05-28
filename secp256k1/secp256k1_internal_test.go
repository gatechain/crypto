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

package secp256k1

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	underlyingSecp256k1 "github.com/btcsuite/btcd/btcec"
)

func Test_genPrivKey(t *testing.T) {

	empty := make([]byte, 32)
	oneB := big.NewInt(1).Bytes()
	onePadded := make([]byte, 32)
	copy(onePadded[32-len(oneB):32], oneB)
	t.Logf("one padded: %v, len=%v", onePadded, len(onePadded))

	validOne := append(empty, onePadded...)
	tests := []struct {
		name        string
		notSoRand   []byte
		shouldPanic bool
	}{
		{"empty bytes (panics because 1st 32 bytes are zero and 0 is not a valid field element)", empty, true},
		{"curve order: N", underlyingSecp256k1.S256().N.Bytes(), true},
		{"valid because 0 < 1 < N", validOne, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldPanic {
				require.Panics(t, func() {
					genPrivKey(bytes.NewReader(tt.notSoRand))
				})
				return
			}
			got := genPrivKey(bytes.NewReader(tt.notSoRand))
			fe := new(big.Int).SetBytes(got[:])
			require.True(t, fe.Cmp(underlyingSecp256k1.S256().N) < 0)
			require.True(t, fe.Sign() > 0)
		})
	}
}
