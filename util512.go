// Copyright (C) 2019 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package crypto

import (
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"github.com/gatechain/gatemint/protocol"
)

// Hashable is an interface implemented by an object that can be represented
// with a sequence of bytes to be hashed or signed, together with a type ID
// to distinguish different types of objects.
//type Hashable interface {
//	ToBeHashed() (protocol.HashID, []byte)
//}
//
//func hashRep(h Hashable) []byte {
//	hashid, data := h.ToBeHashed()
//	return append([]byte(hashid), data...)
//}

// DigestSize is the number of bytes in the preferred hash Digest used here.
const DigestSize512 = sha512.Size

// Digest512 represents a 64-byte value holding the 512-bit Hash digest.
type Digest512 [DigestSize512]byte

// String returns the digest in a human-readable Base32 string
func (d Digest512) String() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(d[:])
}

// TrimUint64 returns the top 64 bits of the digest and converts to uint64
func (d Digest512) TrimUint64() uint64 {
	return binary.LittleEndian.Uint64(d[:8])
}

// IsZero return true if the digest contains only zeros, false otherwise
func (d Digest512) IsZero() bool {
	return d == Digest512{}
}

// DigestFromString converts a string to a Digest
func DigestFromString(str string) (d Digest512, err error) {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(str)
	if err != nil {
		return d, err
	}
	if len(decoded) != len(d) {
		msg := fmt.Sprintf(`Attempted to decode a string which was not a Digest512: "%v"`, str)
		return d, errors.New(msg)
	}
	copy(d[:], decoded[:])
	return d, err
}

// Hash computes the SHASum512_256 hash of an array of bytes
func Hash(data []byte) Digest512 {
	return sha512.Sum512(data)
}

// HashObj computes a hash of a Hashable object and its type
func HashObj(h Hashable) Digest512 {
	return Hash(hashRep(h))
}

// NewHash returns a sha512-256 object to do the same operation as Hash()
func NewHash() hash.Hash {
	return sha512.New()
}
