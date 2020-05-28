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

package tmhash_test

import (
	"crypto/sha256"
	"testing"

	"github.com/gatechain/crypto/tmhash"
	"github.com/stretchr/testify/assert"
)

func TestHash(t *testing.T) {
	testVector := []byte("abc")
	hasher := tmhash.New()
	hasher.Write(testVector)
	bz := hasher.Sum(nil)

	bz2 := tmhash.Sum(testVector)

	hasher = sha256.New()
	hasher.Write(testVector)
	bz3 := hasher.Sum(nil)

	assert.Equal(t, bz, bz2)
	assert.Equal(t, bz, bz3)
}

func TestHashTruncated(t *testing.T) {
	testVector := []byte("abc")
	hasher := tmhash.NewTruncated()
	hasher.Write(testVector)
	bz := hasher.Sum(nil)

	bz2 := tmhash.SumTruncated(testVector)

	hasher = sha256.New()
	hasher.Write(testVector)
	bz3 := hasher.Sum(nil)
	bz3 = bz3[:tmhash.TruncatedSize]

	assert.Equal(t, bz, bz2)
	assert.Equal(t, bz, bz3)
}
