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
			want: "301105cd4b8a14ecf2362a188dce2c2c7fd653fc0224ef3c20025ed908e7fe575c2d59223f424dd0d5de8e451e5ba1a45a39806353c955d744e686cf3321b5550aaa64622d0848e8b7a625ae98eea2d08a5262aaffca2c6b6fe1d82120a104be",
		},
		{
			name: "seed2",
			args: args{mnemonicToSeed("advice process birth april short trust crater change bacon monkey medal garment " +
				"gorilla ranch hour rival razor call lunar mention taste vacant woman sister"), "44'/1'/1'/0/4"},
			want: "805819945328fafae27524b101a5c56e10d15d868b775dab3d1460069ac64a4b9fee7dfd60e450cebbda7dd79c41f31ed2ce636c6a33ed870e696d2693d905863bdc642c05cccf300aebcbacf95a51d31a93a343ff16acd3ad5a41bf749f8a94",
		},
		{
			name: "seed3",
			args: args{mnemonicToSeed("idea naive region square margin day captain habit " +
				"gun second farm pact pulse someone armed"), "44'/0'/0'/0/420"},
			want: "b8f1eede959d92ad7a9f36d5be8a30a92a33772bfed2615798ed4952591616445e5ebb87f8fffdc344a458689412d39c133b58668a8ee3d838dcdb73cadd629fc473fe84d04c1eeba7b6f2ad50e6304506853c6adea16da01cc1f57de357dfb4",
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
