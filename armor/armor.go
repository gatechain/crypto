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
	"bytes"
	"fmt"
	"io/ioutil"

	"golang.org/x/crypto/openpgp/armor"
)

func EncodeArmor(blockType string, headers map[string]string, data []byte) string {
	buf := new(bytes.Buffer)
	w, err := armor.Encode(buf, blockType, headers)
	if err != nil {
		panic(fmt.Errorf("could not encode ascii armor: %s", err))
	}
	_, err = w.Write(data)
	if err != nil {
		panic(fmt.Errorf("could not encode ascii armor: %s", err))
	}
	err = w.Close()
	if err != nil {
		panic(fmt.Errorf("could not encode ascii armor: %s", err))
	}
	return buf.String()
}

func DecodeArmor(armorStr string) (blockType string, headers map[string]string, data []byte, err error) {
	buf := bytes.NewBufferString(armorStr)
	block, err := armor.Decode(buf)
	if err != nil {
		return "", nil, nil, err
	}
	data, err = ioutil.ReadAll(block.Body)
	if err != nil {
		return "", nil, nil, err
	}
	return block.Type, block.Header, data, nil
}
