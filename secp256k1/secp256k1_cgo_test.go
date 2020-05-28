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

// +build libsecp256k1

package secp256k1

import (
	"github.com/magiconair/properties/assert"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrivKeySecp256k1SignVerify(t *testing.T) {
	msg := []byte("A.1.2 ECC Key Pair Generation by Testing Candidates")
	priv := GenPrivKey()
	tests := []struct {
		name             string
		privKey          PrivKeySecp256k1
		wantSignErr      bool
		wantVerifyPasses bool
	}{
		{name: "valid sign-verify round", privKey: priv, wantSignErr: false, wantVerifyPasses: true},
		{name: "invalid private key", privKey: [32]byte{}, wantSignErr: true, wantVerifyPasses: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.privKey.Sign(msg)
			if tt.wantSignErr {
				require.Error(t, err)
				t.Logf("Got error: %s", err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)

			pub := tt.privKey.PubKey()
			assert.Equal(t, tt.wantVerifyPasses, pub.VerifyBytes(msg, got))
		})
	}
}
