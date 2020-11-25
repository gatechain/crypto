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

package secp256k1

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	secp256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/cosmos/go-bip39"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/gatechain/crypto"
	"github.com/maoxs2/go-ripemd"
	"github.com/tendermint/go-amino"
	"io"
	"math/big"
	"strconv"
	"strings"
)

//-------------------------------------
const (
	PrivKeyAminoName = "gatechain/PrivKeySecp256k1"
	PubKeyAminoName  = "gatechain/PubKeySecp256k1"
)

var cdc = amino.NewCodec()

func init() {
	cdc.RegisterInterface((*crypto.PubKey)(nil), nil)
	cdc.RegisterConcrete(PubKeySecp256k1{},
		PubKeyAminoName, nil)

	cdc.RegisterInterface((*crypto.PrivKey)(nil), nil)
	cdc.RegisterConcrete(PrivKeySecp256k1{},
		PrivKeyAminoName, nil)
}

//-------------------------------------

var _ crypto.PrivKey = PrivKeySecp256k1{}

// PrivKeySecp256k1 implements PrivKey.
type PrivKeySecp256k1 [32]byte

// Bytes marshalls the private key using amino encoding.
func (privKey PrivKeySecp256k1) Bytes() []byte {
	return cdc.MustMarshalBinaryBare(privKey)
}

// PubKey performs the point-scalar multiplication from the privKey on the
// generator point to get the pubkey.
func (privKey PrivKeySecp256k1) PubKey() crypto.PubKey {
	_, pubkeyObject := secp256k1.PrivKeyFromBytes(secp256k1.S256(), privKey[:])
	var pubkeyBytes PubKeySecp256k1
	copy(pubkeyBytes[:], pubkeyObject.SerializeCompressed())
	return pubkeyBytes
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (privKey PrivKeySecp256k1) Equals(other crypto.PrivKey) bool {
	if otherSecp, ok := other.(PrivKeySecp256k1); ok {
		return subtle.ConstantTimeCompare(privKey[:], otherSecp[:]) == 1
	}
	return false
}

// GenPrivKey generates a new ECDSA private key on curve secp256k1 private key.
// It uses OS randomness to generate the private key.
func GenPrivKey() PrivKeySecp256k1 {
	return genPrivKey(crypto.CReader())
}

// GenerateKey generates a new random private key. It returns an error upon
// failure.
func SecpDeriveKey(mnemonic string, bip39Passphrase, hdPath string) PrivKeySecp256k1 {
	var dPriv PrivKeySecp256k1
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)

	masterPriv, ch := ComputeMastersFromSeed(seed)

	copy(dPriv[:], masterPriv[:])
	if len(hdPath) == 0 {
		return dPriv
	}
	privBz, err := DerivePrivateKeyForPath(masterPriv, ch, hdPath)
	if err != nil {
		return PrivKeySecp256k1{}
	}
	dPriv = privBz
	return dPriv
}

// genPrivKey generates a new secp256k1 private key using the provided reader.
func genPrivKey(rand io.Reader) PrivKeySecp256k1 {
	var privKeyBytes [32]byte
	d := new(big.Int)
	for {
		privKeyBytes = [32]byte{}
		_, err := io.ReadFull(rand, privKeyBytes[:])
		if err != nil {
			panic(err)
		}

		d.SetBytes(privKeyBytes[:])
		// break if we found a valid point (i.e. > 0 and < N == curverOrder)
		isValidFieldElement := 0 < d.Sign() && d.Cmp(secp256k1.S256().N) < 0
		if isValidFieldElement {
			break
		}
	}

	return PrivKeySecp256k1(privKeyBytes)
}

var one = new(big.Int).SetInt64(1)

// GenPrivKeySecp256k1 hashes the secret with SHA2, and uses
// that 32 byte output to create the private key.
//
// It makes sure the private key is a valid field element by setting:
//
// c = sha256(secret)
// k = (c mod (n − 1)) + 1, where n = curve order.
//
// NOTE: secret should be the output of a KDF like bcrypt,
// if it's derived from user input.
func GenPrivKeySecp256k1(secret []byte) PrivKeySecp256k1 {
	secHash := sha256.Sum256(secret)
	// to guarantee that we have a valid field element, we use the approach of:
	// "Suite B Implementer’s Guide to FIPS 186-3", A.2.1
	// https://apps.nsa.gov/iaarchive/library/ia-guidance/ia-solutions-for-classified/algorithm-guidance/suite-b-implementers-guide-to-fips-186-3-ecdsa.cfm
	// see also https://github.com/golang/go/blob/0380c9ad38843d523d9c9804fe300cb7edd7cd3c/src/crypto/ecdsa/ecdsa.go#L89-L101
	fe := new(big.Int).SetBytes(secHash[:])
	n := new(big.Int).Sub(secp256k1.S256().N, one)
	fe.Mod(fe, n)
	fe.Add(fe, one)

	feB := fe.Bytes()
	var privKey32 [32]byte
	// copy feB over to fixed 32 byte privKey32 and pad (if necessary)
	copy(privKey32[32-len(feB):32], feB)

	return PrivKeySecp256k1(privKey32)
}

//-------------------------------------

var _ crypto.PubKey = PubKeySecp256k1{}

// PubKeySecp256k1Size is comprised of 32 bytes for one field element
// (the x-coordinate), plus one byte for the parity of the y-coordinate.
const PubKeySecp256k1Size = 33

// PubKeySecp256k1 implements crypto.PubKey.
// It is the compressed form of the pubkey. The first byte depends is a 0x02 byte
// if the y-coordinate is the lexicographically largest of the two associated with
// the x-coordinate. Otherwise the first byte is a 0x03.
// This prefix is followed with the x-coordinate.
type PubKeySecp256k1 [PubKeySecp256k1Size]byte

// Address returns a Bitcoin style addresses: RIPEMD160(SHA256(pubkey))
func (pubKey PubKeySecp256k1) Address() crypto.Address {
	pubk, err := ethcrypto.DecompressPubkey(pubKey[:])
	if err != nil {
		panic(err)
	}

	return ethcrypto.PubkeyToAddress(*pubk).Bytes()
}

// Address returns a Bitcoin style addresses: RIPEMD320(SHA512(pubkey))
func (pubKey PubKeySecp256k1) Address512() crypto.Address {
	hasherSHA512 := sha512.New()
	hasherSHA512.Write(pubKey[:]) // does not error
	sha := hasherSHA512.Sum(nil)

	hasherRIPEMD320 := ripemd.New320()
	hasherRIPEMD320.Write(sha) // does not error
	return crypto.Address(hasherRIPEMD320.Sum(nil))
}

// Bytes returns the pubkey marshalled with amino encoding.
func (pubKey PubKeySecp256k1) Bytes() []byte {
	bz, err := cdc.MarshalBinaryBare(pubKey)
	if err != nil {
		panic(err)
	}
	return bz
}

func (pubKey PubKeySecp256k1) String() string {
	return fmt.Sprintf("PubKeySecp256k1{%X}", pubKey[:])
}

func (pubKey PubKeySecp256k1) Equals(other crypto.PubKey) bool {
	if otherSecp, ok := other.(PubKeySecp256k1); ok {
		return bytes.Equal(pubKey[:], otherSecp[:])
	}
	return false
}




// DERIVE SECP256K1

// DerivePrivateKeyForPath derives the private key by following the BIP 32/44 path from privKeyBytes,
// using the given chainCode.
func DerivePrivateKeyForPath(privKeyBytes [32]byte, chainCode [32]byte, path string) ([32]byte, error) {
	data := privKeyBytes
	parts := strings.Split(path, "/")
	for _, part := range parts {
		// do we have an apostrophe?
		harden := part[len(part)-1:] == "'"
		// harden == private derivation, else public derivation:
		if harden {
			part = part[:len(part)-1]
		}
		idx, err := strconv.Atoi(part)
		if err != nil {
			return [32]byte{}, fmt.Errorf("invalid BIP 32 path: %s", err)
		}
		if idx < 0 {
			return [32]byte{}, errors.New("invalid BIP 32 path: index negative ot too large")
		}
		data, chainCode = derivePrivateKey(data, chainCode, uint32(idx), harden)
	}
	var derivedKey [32]byte
	n := copy(derivedKey[:], data[:])
	if n != 32 || len(data) != 32 {
		return [32]byte{}, fmt.Errorf("expected a (secp256k1) key of length 32, got length: %v", len(data))
	}

	return derivedKey, nil
}


// derivePrivateKey derives the private key with index and chainCode.
// If harden is true, the derivation is 'hardened'.
// It returns the new private key and new chain code.
// For more information on hardened keys see:
//  - https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
func derivePrivateKey(privKeyBytes [32]byte, chainCode [32]byte, index uint32, harden bool) ([32]byte, [32]byte) {
	var data []byte
	if harden {
		index |= 0x80000000
		data = append([]byte{byte(0)}, privKeyBytes[:]...)
	} else {
		// this can't return an error:
		_, ecPub := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes[:])
		pubkeyBytes := ecPub.SerializeCompressed()
		data = pubkeyBytes

		/* By using btcec, we can remove the dependency on tendermint/crypto/secp256k1
		pubkey := secp256k1.PrivKeySecp256k1(privKeyBytes).PubKey()
		public := pubkey.(secp256k1.PubKeySecp256k1)
		data = public[:]
		*/
	}
	data = append(data, uint32ToBytes(index)...)
	data2, chainCode2 := i64(chainCode[:], data)
	x := addScalars(privKeyBytes[:], data2[:])
	return x, chainCode2
}

func uint32ToBytes(i uint32) []byte {
	b := [4]byte{}
	binary.BigEndian.PutUint32(b[:], i)
	return b[:]
}

// modular big endian addition
func addScalars(a []byte, b []byte) [32]byte {
	aInt := new(big.Int).SetBytes(a)
	bInt := new(big.Int).SetBytes(b)
	sInt := new(big.Int).Add(aInt, bInt)
	x := sInt.Mod(sInt, btcec.S256().N).Bytes()
	x2 := [32]byte{}
	copy(x2[32-len(x):], x)
	return x2
}

// ComputeMastersFromSeed returns the master public key, master secret, and chain code in hex.
func ComputeMastersFromSeed(seed []byte) (secret [32]byte, chainCode [32]byte) {
	masterSecret := []byte("Bitcoin seed")
	secret, chainCode = i64(masterSecret, seed)
	return
}

// i64 returns the two halfs of the SHA512 HMAC of key and data.
func i64(key []byte, data []byte) (il [32]byte, ir [32]byte) {
	mac := hmac.New(sha512.New, key)
	// sha512 does not err
	_, _ = mac.Write(data)

	I := mac.Sum(nil)
	copy(il[:], I[:32])
	copy(ir[:], I[32:])

	return
}