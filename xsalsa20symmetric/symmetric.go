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
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"

	"github.com/gatechain/crypto"
)

// TODO, make this into a struct that implements crypto.Symmetric.

const nonceLen = 24
const secretLen = 32

// secret must be 32 bytes long. Use something like Sha256(Bcrypt(passphrase))
// The ciphertext is (secretbox.Overhead + 24) bytes longer than the plaintext.
func EncryptSymmetric(plaintext []byte, secret []byte) (ciphertext []byte) {
	if len(secret) != secretLen {
		panic(fmt.Sprintf("Secret must be 32 bytes long, got len %v", len(secret)))
	}
	nonce := crypto.CRandBytes(nonceLen)
	nonceArr := [nonceLen]byte{}
	copy(nonceArr[:], nonce)
	secretArr := [secretLen]byte{}
	copy(secretArr[:], secret)
	ciphertext = make([]byte, nonceLen+secretbox.Overhead+len(plaintext))
	copy(ciphertext, nonce)
	secretbox.Seal(ciphertext[nonceLen:nonceLen], plaintext, &nonceArr, &secretArr)
	return ciphertext
}

// secret must be 32 bytes long. Use something like Sha256(Bcrypt(passphrase))
// The ciphertext is (secretbox.Overhead + 24) bytes longer than the plaintext.
func DecryptSymmetric(ciphertext []byte, secret []byte) (plaintext []byte, err error) {
	if len(secret) != secretLen {
		panic(fmt.Sprintf("Secret must be 32 bytes long, got len %v", len(secret)))
	}
	if len(ciphertext) <= secretbox.Overhead+nonceLen {
		return nil, errors.New("ciphertext is too short")
	}
	nonce := ciphertext[:nonceLen]
	nonceArr := [nonceLen]byte{}
	copy(nonceArr[:], nonce)
	secretArr := [secretLen]byte{}
	copy(secretArr[:], secret)
	plaintext = make([]byte, len(ciphertext)-nonceLen-secretbox.Overhead)
	_, ok := secretbox.Open(plaintext[:0], ciphertext[nonceLen:], &nonceArr, &secretArr)
	if !ok {
		return nil, errors.New("ciphertext decryption failed")
	}
	return plaintext, nil
}
