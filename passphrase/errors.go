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

package passphrase

import (
	"fmt"
)

var errWrongKeyLen = fmt.Errorf("key length must be %d bytes", keyLenBytes)
var errWrongMnemonicLen = fmt.Errorf("mnemonic must be %d words", mnemonicLenWords)
var errWrongChecksum = fmt.Errorf("checksum failed to validate")
