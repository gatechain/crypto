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

package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gatechain/crypto"
)

// the purpose of this test is primarily to ensure that the randomness
// generation won't error.
func TestRandomConsistency(t *testing.T) {
	x1 := crypto.CRandBytes(256)
	x2 := crypto.CRandBytes(256)
	x3 := crypto.CRandBytes(256)
	x4 := crypto.CRandBytes(256)
	x5 := crypto.CRandBytes(256)
	require.NotEqual(t, x1, x2)
	require.NotEqual(t, x3, x4)
	require.NotEqual(t, x4, x5)
	require.NotEqual(t, x1, x5)
}
