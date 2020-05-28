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

package ed25519_test

import (
	"fmt"
	"testing"

	"github.com/gatechain/crypto"
	"github.com/gatechain/crypto/ed25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignAndValidateEd25519(t *testing.T) {

	for i := 0; i < 10000; i++ {
		privKey := ed25519.GenPrivKey()
		pubKey := privKey.PubKey()

		msg := crypto.CRandBytes(128)
		sig, err := privKey.Sign(msg)
		require.Nil(t, err)

		// Test the signature
		assert.True(t, pubKey.VerifyBytes(msg, sig))

		// Mutate the signature, just one bit.
		sig[7] ^= byte(0x01)

		assert.False(t, pubKey.VerifyBytes(msg, sig))

		if i%1000 == 0 {
			fmt.Println(pubKey.Address())
			fmt.Println(pubKey.Address512())
		}
	}

}
