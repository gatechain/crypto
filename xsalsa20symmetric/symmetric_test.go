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

package xsalsa20symmetric

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.org/x/crypto/bcrypt"

	"github.com/gatechain/crypto"
)

func TestSimple(t *testing.T) {

	plaintext := []byte("sometext")
	secret := []byte("somesecretoflengththirtytwo===32")
	ciphertext := EncryptSymmetric(plaintext, secret)
	plaintext2, err := DecryptSymmetric(ciphertext, secret)

	require.Nil(t, err, "%+v", err)
	assert.Equal(t, plaintext, plaintext2)
}

func TestSimpleWithKDF(t *testing.T) {

	plaintext := []byte("sometext")
	secretPass := []byte("somesecret")
	secret, err := bcrypt.GenerateFromPassword(secretPass, 12)
	if err != nil {
		t.Error(err)
	}
	secret = crypto.Sha256(secret)

	ciphertext := EncryptSymmetric(plaintext, secret)
	plaintext2, err := DecryptSymmetric(ciphertext, secret)

	require.Nil(t, err, "%+v", err)
	assert.Equal(t, plaintext, plaintext2)
}
