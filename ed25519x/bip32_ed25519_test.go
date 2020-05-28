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

import (
	"encoding/hex"
	"github.com/cosmos/go-bip39"
	"github.com/gatechain/crypto"
	"github.com/gatechain/crypto/ed25519"
	"github.com/stretchr/testify/require"
	"testing"
)

var defaultBIP39Passphrase = ""

// return bip39 seed with empty passphrase
func mnemonicToSeed(mnemonic string) []byte {
	return bip39.NewSeed(mnemonic, defaultBIP39Passphrase)
}
func TestXPrv_Derive(t *testing.T) {
	type args struct {
		seed []byte
		path string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "seed1",
			args: args{mnemonicToSeed("barrel original fuel morning among eternal " +
				"filter ball stove pluck matrix mechanic"), "44'/118'/0'/0/0"},
			want: "f00d2ed18ab5bbf4b52a19f827aa2cfaa0b7658e85c0ff6ea9b5fadb0be7fe577a68b8c7ebf3cbfecd95088664ea5d361ef714396eadca7780fbd0e01e69ba80ad310f3628033cc419c0e17a02bad336af5cd4a381a3df9c95da1b32286aa554",
		},
		{
			name: "seed2",
			args: args{mnemonicToSeed("advice process birth april short trust crater change bacon monkey medal garment " +
				"gorilla ranch hour rival razor call lunar mention taste vacant woman sister"), "44'/1'/1'/0/4"},
			want: "207f092e17cc9fd9ef319bc5c5d80a7961778de07db85422591c380587c64a4be7be8ec1b426a5c5c783263cbc13d0770e600ea11d0b1bc0c9d3cb64dcd1ddd4be424f9af3e6d0b4343a5ee78a73d161ae7d7d7fd9e259bcaaedeb91a5146381",
		},
		{
			name: "seed3",
			args: args{mnemonicToSeed("idea naive region square margin day captain habit " +
				"gun second farm pact pulse someone armed"), "44'/0'/0'/0/420"},
			want: "58d3b68b06faaab04e06d1f16f9fe630d1ee632fc3f163af63cda13a57161644f75ada0a6ec4b831b65881b5dff5cdadfca573311bf3aafcf2e9c75bcffbcc928e4aa41752da49d3beb2749bfd4b1e7c751fa6aa211dd5694616243d9c9e93d6",
		},
		{
			name: "seed4",
			args: args{mnemonicToSeed("monitor flock loyal sick object grunt duty ride develop assault harsh history"), "0/7"},
			want: "101788ae8108877d65ed89674eb72df72df1ad03c4d87b392941e08de9636e401b9c9f02211dcc1800ff2697db927e62afde82978940ebc559197d79056f77ea7412e0f907947072151e53a60d7a056c84c26e4f4bacc6f9d3a86dcf8e709d44",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gxfs := GenerateXprvFromSeed(tt.args.seed)
			xprv, _ := DerivePrivateKeyFromPath(gxfs, tt.args.path)
			if got := xprv.String(); got != tt.want {
				t.Errorf("XPrv.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEdd25519Priv(t *testing.T) {
	gxfs := GenerateXprvFromSeed(mnemonicToSeed("barrel original fuel morning among eternal " +
		"filter ball stove pluck matrix mechanic"))
	xprv, err := DerivePrivateKeyFromPath(gxfs, "44'/0'/0'/0/420")
	require.Nil(t, err)
	t.Log("seed", hex.EncodeToString(mnemonicToSeed("barrel original fuel morning among eternal "+
		"filter ball stove pluck matrix mechanic")))
	t.Log("gxfs", hex.EncodeToString(gxfs[:]))
	t.Log("xprv1", xprv.String())
	xpub := xprv.PubKey().(XPub)
	t.Log("xpub", hex.EncodeToString(xpub[:]))

	xprivate := xprv.EDPrivKey()
	xpublic := xprv.EDPubKey()
	public := xprivate.PubKey().(ed25519.PubKeyEd25519)

	t.Log("xprv   ", hex.EncodeToString(xprivate[:]), "len", len(xprivate))
	t.Log("xpublic", hex.EncodeToString(xpublic[:]), "len", len(xpublic))
	t.Log("public ", hex.EncodeToString(public[:]), "len", len(public))
	require.True(t, xprivate.PubKey().Equals(xpublic))

}
func TestSignAndValidateEd25519(t *testing.T) {
	for i := 0; i < 10000; i++ {
		gxfs := GenerateXprvFromSeed(crypto.CRandBytes(128))
		xprv, err := DerivePrivateKeyFromPath(gxfs, "44'/0'/0'/0/420")
		require.Nil(t, err)

		xprivate := xprv.EDPrivKey()
		xpublic := xprv.EDPubKey()

		msg := crypto.CRandBytes(128)
		sig, err := xprivate.Sign(msg)
		require.Nil(t, err)
		require.True(t, xpublic.VerifyBytes(msg, sig))

		sig[7] ^= byte(0x01)
		require.False(t, xpublic.VerifyBytes(msg, sig))
	}

}

func TestXPrvXPub(t *testing.T) {
	xprivate := GenPrivKey()
	xpublic := xprivate.PubKey()
	t.Log("xprv   ", hex.EncodeToString(xprivate.Bytes()[:]), "len", len(xprivate.Bytes()))
	t.Log("xpublic", hex.EncodeToString(xpublic.Bytes()[:]), "len", len(xpublic.Bytes()))

	msg := crypto.CRandBytes(128)
	sig, err := xprivate.Sign(msg)
	require.Nil(t, err)
	require.True(t, xpublic.VerifyBytes(msg, sig))

	sig[7] ^= byte(0x01)
	require.False(t, xpublic.VerifyBytes(msg, sig))
}
