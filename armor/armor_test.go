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

package armor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSimpleArmor(t *testing.T) {
	blockType := "MINT TEST"
	data := []byte("somedata")
	armorStr := EncodeArmor(blockType, nil, data)

	// Decode armorStr and test for equivalence.
	blockType2, _, data2, err := DecodeArmor(armorStr)
	require.Nil(t, err, "%+v", err)
	assert.Equal(t, blockType, blockType2)
	assert.Equal(t, data, data2)
}
