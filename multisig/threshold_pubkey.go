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

package multisig

import (
	"crypto/sha512"
	"github.com/gatechain/crypto"
	"github.com/maoxs2/go-ripemd"
)

// PubKeyMultisigThreshold implements a K of N threshold multisig.
type PubKeyMultisigThreshold struct {
	K       uint            `json:"threshold"`
	PubKeys []crypto.PubKey `json:"pubkeys"`
}

var _ crypto.PubKey = PubKeyMultisigThreshold{}

// NewPubKeyMultisigThreshold returns a new PubKeyMultisigThreshold.
// Panics if len(pubkeys) < k or 0 >= k.
func NewPubKeyMultisigThreshold(k int, pubkeys []crypto.PubKey) crypto.PubKey {
	if k <= 0 {
		panic("threshold k of n multisignature: k <= 0")
	}
	if len(pubkeys) < k {
		panic("threshold k of n multisignature: len(pubkeys) < k")
	}
	for _, pubkey := range pubkeys {
		if pubkey == nil {
			panic("nil pubkey")
		}
	}
	return PubKeyMultisigThreshold{uint(k), pubkeys}
}

// VerifyBytes expects sig to be an amino encoded version of a MultiSignature.
// Returns true iff the multisignature contains k or more signatures
// for the correct corresponding keys,
// and all signatures are valid. (Not just k of the signatures)
// The multisig uses a bitarray, so multiple signatures for the same key is not
// a concern.
func (pk PubKeyMultisigThreshold) VerifyBytes(msg []byte, marshalledSig []byte) bool {
	var sig Multisignature
	err := cdc.UnmarshalBinaryBare(marshalledSig, &sig)
	if err != nil {
		return false
	}
	size := sig.BitArray.Size()
	// ensure bit array is the correct size
	if len(pk.PubKeys) != size {
		return false
	}
	// ensure size of signature list
	if len(sig.Sigs) < int(pk.K) || len(sig.Sigs) > size {
		return false
	}
	// ensure at least k signatures are set
	if sig.BitArray.NumTrueBitsBefore(size) < int(pk.K) {
		return false
	}
	// index in the list of signatures which we are concerned with.
	sigIndex := 0
	for i := 0; i < size; i++ {
		if sig.BitArray.GetIndex(i) {
			if !pk.PubKeys[i].VerifyBytes(msg, sig.Sigs[sigIndex]) {
				return false
			}
			sigIndex++
		}
	}
	return true
}

// Bytes returns the amino encoded version of the PubKeyMultisigThreshold
func (pk PubKeyMultisigThreshold) Bytes() []byte {
	return cdc.MustMarshalBinaryBare(pk)
}

// Address returns tmhash(PubKeyMultisigThreshold.Bytes())
func (pk PubKeyMultisigThreshold) Address512() crypto.Address {
	return crypto.AddressHash(pk.Bytes())
}

// Equals returns true iff pk and other both have the same number of keys, and
// all constituent keys are the same, and in the same order.
func (pk PubKeyMultisigThreshold) Equals(other crypto.PubKey) bool {
	otherKey, sameType := other.(PubKeyMultisigThreshold)
	if !sameType {
		return false
	}
	if pk.K != otherKey.K || len(pk.PubKeys) != len(otherKey.PubKeys) {
		return false
	}
	for i := 0; i < len(pk.PubKeys); i++ {
		if !pk.PubKeys[i].Equals(otherKey.PubKeys[i]) {
			return false
		}
	}
	return true
}

func (pk PubKeyMultisigThreshold) Address() crypto.Address {
	hasherSHA512 := sha512.New()
	hasherSHA512.Write(pk.Bytes()[:]) // does not error
	sha := hasherSHA512.Sum(nil)

	hasherRIPEMD320 := ripemd.New320()
	hasherRIPEMD320.Write(sha) // does not error
	return crypto.Address(hasherRIPEMD320.Sum(nil))
}
