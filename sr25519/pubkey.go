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

package sr25519

import (
	"bytes"
	"crypto/sha512"
	"fmt"
	"github.com/maoxs2/go-ripemd"

	"github.com/gatechain/crypto"
	"github.com/gatechain/crypto/tmhash"

	schnorrkel "github.com/ChainSafe/go-schnorrkel"
)

var _ crypto.PubKey = PubKeySr25519{}

// PubKeySr25519Size is the number of bytes in an Sr25519 public key.
const PubKeySr25519Size = 32

// PubKeySr25519 implements crypto.PubKey for the Sr25519 signature scheme.
type PubKeySr25519 [PubKeySr25519Size]byte

// Address is the SHA256-20 of the raw pubkey bytes.
func (pubKey PubKeySr25519) Address() crypto.Address {
	return crypto.Address(tmhash.SumTruncated(pubKey[:]))
}

// Bytes marshals the PubKey using amino encoding.
func (pubKey PubKeySr25519) Bytes() []byte {
	bz, err := cdc.MarshalBinaryBare(pubKey)
	if err != nil {
		panic(err)
	}
	return bz
}

func (pubKey PubKeySr25519) VerifyBytes(msg []byte, sig []byte) bool {
	// make sure we use the same algorithm to sign
	if len(sig) != SignatureSize {
		return false
	}
	var sig64 [SignatureSize]byte
	copy(sig64[:], sig)

	publicKey := &(schnorrkel.PublicKey{})
	err := publicKey.Decode(pubKey)
	if err != nil {
		return false
	}

	signingContext := schnorrkel.NewSigningContext([]byte{}, msg)

	signature := &(schnorrkel.Signature{})
	err = signature.Decode(sig64)
	if err != nil {
		return false
	}

	return publicKey.Verify(signature, signingContext)
}

func (pubKey PubKeySr25519) String() string {
	return fmt.Sprintf("PubKeySr25519{%X}", pubKey[:])
}

// Equals - checks that two public keys are the same time
// Runs in constant time based on length of the keys.
func (pubKey PubKeySr25519) Equals(other crypto.PubKey) bool {
	if otherEd, ok := other.(PubKeySr25519); ok {
		return bytes.Equal(pubKey[:], otherEd[:])
	}
	return false
}

func (pubKey PubKeySr25519) Address512() crypto.Address {
	hasherSHA512 := sha512.New()
	hasherSHA512.Write(pubKey[:]) // does not error
	sha := hasherSHA512.Sum(nil)

	hasherRIPEMD320 := ripemd.New320()
	hasherRIPEMD320.Write(sha) // does not error
	return crypto.Address(hasherRIPEMD320.Sum(nil))
}
