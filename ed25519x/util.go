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

package ed25519x

import "github.com/gatechain/crypto/ed25519/edwards25519"

func add28Mul8(kl, zl []byte) []byte {
	var carry uint16 = 0
	var out [32]byte

	for i := 0; i < 28; i++ {
		r := uint16(kl[i]) + uint16(zl[i])<<3 + carry
		out[i] = byte(r & 0xff)
		carry = r >> 8
	}

	for i := 28; i < 32; i++ {
		r := uint16(kl[i]) + carry
		out[i] = byte(r & 0xff)
		carry = r >> 8
	}

	return out[:]
}

func add256Bits(kr, zr []byte) []byte {
	var carry uint16 = 0
	var out [32]byte

	for i := 0; i < 32; i++ {
		r := uint16(kr[i]) + uint16(zr[i]) + carry
		out[i] = byte(r & 0xff)
		carry = r >> 8
	}

	return out[:]
}

func pointLeft(pubkey, zl []byte) []byte {
	var hBytes [32]byte
	kl := make([]byte, 32)
	copy(hBytes[:], add28Mul8(kl, zl)[:32])

	var A edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&A, &hBytes)

	var zl8b [32]byte
	A.ToBytes(&zl8b)

	var key [32]byte
	key[0] = 1

	var ap [32]byte
	copy(ap[:], pubkey)
	A.FromBytes(&ap)

	var Ai edwards25519.ProjectiveGroupElement
	edwards25519.GeDoubleScalarMultVartime(&Ai, &key, &A, &zl8b)
	Ai.ToBytes(&key)

	return key[:]
}
