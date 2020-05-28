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

package crypto

import (
	crand "crypto/rand"
	"encoding/hex"
	"io"
)

// This only uses the OS's randomness
func randBytes(numBytes int) []byte {
	b := make([]byte, numBytes)
	_, err := crand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

// This only uses the OS's randomness
func CRandBytes(numBytes int) []byte {
	return randBytes(numBytes)
}

// CRandHex returns a hex encoded string that's floor(numDigits/2) * 2 long.
//
// Note: CRandHex(24) gives 96 bits of randomness that
// are usually strong enough for most purposes.
func CRandHex(numDigits int) string {
	return hex.EncodeToString(CRandBytes(numDigits / 2))
}

// Returns a crand.Reader.
func CReader() io.Reader {
	return crand.Reader
}
