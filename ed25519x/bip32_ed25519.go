package ed25519x

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gatechain/crypto"
	"github.com/gatechain/crypto/ed25519/edwards25519"
	"github.com/maoxs2/go-ripemd"
	"github.com/tendermint/go-amino"
	"strconv"
	"strings"

	"github.com/gatechain/crypto/ed25519"
)

const (
	GateCoinFullPath = "44'/669'/0'/0/0"

	HardIndex = 0x80000000
	XPrvSize  = 96

	XPrivKeyAminoName = "gatechain/XPrv"
	XPubKeyAminoName  = "gatechain/XPub"

	XPubSize = 64
)

var cdc = amino.NewCodec()

func init() {
	cdc.RegisterInterface((*crypto.PubKey)(nil), nil)
	cdc.RegisterConcrete(XPub{}, XPubKeyAminoName, nil)

	cdc.RegisterInterface((*crypto.PrivKey)(nil), nil)
	cdc.RegisterConcrete(XPrv{}, XPrivKeyAminoName, nil)
}

var _ crypto.PrivKey = XPrv{}

type XPrv [XPrvSize]byte

func (priv XPrv) Bytes() []byte {
	return cdc.MustMarshalBinaryBare(priv)
}

func (priv XPrv) Sign(message []byte) ([]byte, error) {
	return priv.EDPrivKey().Sign(message)
}

func (priv XPrv) PubKey() crypto.PubKey {
	var xpub [XPubSize]byte
	pub := priv.EDPubKey()
	copy(xpub[:], pub[:])
	copy(xpub[32:], priv[64:])
	return XPub(xpub)
}

func (priv XPrv) Equals(other crypto.PrivKey) bool {
	if otherEd, ok := other.(XPrv); ok {
		return subtle.ConstantTimeCompare(priv[:], otherEd[:]) == 1
	}
	return false
}

func GenPrivKey() XPrv {
	return GenPrivKeyFromPath(GateCoinFullPath)
}

func GenPrivKeyFromPath(fullHdPath string) XPrv {
	xprv, err := DerivePrivateKeyFromPath(GenerateXprvFromSeed(crypto.CRandBytes(128)), fullHdPath)
	if err != nil {
		panic(err)
	}
	return xprv
}

var _ crypto.PubKey = XPub{}

type XPub [XPubSize]byte

func (pubKey XPub) Address512() crypto.Address {
	panic("not supported")
}

func (pubKey XPub) Address() crypto.Address {
	hasherSHA512 := sha512.New()
	hasherSHA512.Write(pubKey[:]) // does not error
	sha := hasherSHA512.Sum(nil)

	hasherRIPEMD320 := ripemd.New320()
	hasherRIPEMD320.Write(sha) // does not error
	return crypto.Address(hasherRIPEMD320.Sum(nil))
}

func (pubKey XPub) Bytes() []byte {
	bz, err := cdc.MarshalBinaryBare(pubKey)
	if err != nil {
		panic(err)
	}
	return bz
}

func (pubKey XPub) VerifyBytes(msg []byte, sig []byte) bool {
	var edpub ed25519.PubKeyEd25519
	copy(edpub[:], pubKey[:])
	return edpub.VerifyBytes(msg, sig)
}

func (pubKey XPub) String() string {
	return fmt.Sprintf("XPubKeyEd25519{%X}", pubKey[:])
}

func (pubKey XPub) Equals(other crypto.PubKey) bool {
	if otherEd, ok := other.(XPub); ok {
		return bytes.Equal(pubKey[:], otherEd[:])
	}

	return false
}

// GenerateXprvFromSeed returns the master private key.
func GenerateXprvFromSeed(seed []byte) XPrv {
	iter := 1
	var xprv [XPrvSize]byte
	for {
		key := hmac.New(sha512.New, seed)
		key.Write([]byte("Root Seed Chain " + strconv.Itoa(iter)))
		digest := key.Sum(nil)
		secretKey := sha512.Sum512(digest[:32])
		right := digest[32:]
		secretKey[0] &= 248
		secretKey[31] &= 63
		secretKey[31] |= 64
		if secretKey[31]&0x20 == 0 {
			copy(xprv[:64], secretKey[:])
			copy(xprv[64:], right[:])
			break
		}
		iter++
	}
	return xprv
}

// DerivePrivateKeyFromPath derives the private key by following the BIP 32/44 path from privKeyBytes
func DerivePrivateKeyFromPath(x XPrv, path string) (XPrv, error) {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if i == 0 && part == "m" {
			continue
		}
		// do we have an apostrophe?
		harden := part[len(part)-1:] == "'"
		// harden == private derivation, else public derivation:
		if harden {
			part = part[:len(part)-1]
		}
		idx, err := strconv.Atoi(part)
		if err != nil {
			return XPrv{}, fmt.Errorf("invalid BIP 32 path: %s", err)
		}
		if idx < 0 {
			return XPrv{}, errors.New("invalid BIP 32 path: index negative ot too large")
		}
		if harden {
			idx |= HardIndex
		}
		x = x.DerivePrv(uint32(idx))
	}
	return x, nil
}

func (priv XPrv) DerivePrv(index uint32) XPrv {
	ekey := append([]byte(nil), priv[:64]...)
	chaincode := append([]byte(nil), priv[64:96]...)

	kl := append([]byte(nil), priv[:32]...)
	kr := append([]byte(nil), priv[32:64]...)

	zmac := hmac.New(sha512.New, chaincode)
	imac := hmac.New(sha512.New, chaincode)

	seri := make([]byte, 4)
	binary.LittleEndian.PutUint32(seri, index)

	if index >= HardIndex {
		_, _ = zmac.Write([]byte{0})
		_, _ = zmac.Write(ekey)
		_, _ = zmac.Write(seri)

		_, _ = imac.Write([]byte{1})
		_, _ = imac.Write(ekey)
		_, _ = imac.Write(seri)
	} else {
		pubkey := priv.EDPubKey()
		_, _ = zmac.Write([]byte{2})
		_, _ = zmac.Write(pubkey[:])
		_, _ = zmac.Write(seri)

		_, _ = imac.Write([]byte{3})
		_, _ = imac.Write(pubkey[:])
		_, _ = imac.Write(seri)
	}

	zout, iout := zmac.Sum(nil), imac.Sum(nil)
	zl, zr := zout[0:32], zout[32:64]

	var result [XPrvSize]byte
	copy(result[0:32], add28Mul8(kl, zl))   // kl
	copy(result[32:64], add256Bits(kr, zr)) // kr
	copy(result[64:96], iout[32:])          // chain code
	return result
}

func (priv XPrv) EDPubKey() ed25519.PubKeyEd25519 {
	var A edwards25519.ExtendedGroupElement

	var hBytes [32]byte
	copy(hBytes[:], priv[:32]) // make sure prvkey is 32 bytes

	edwards25519.GeScalarMultBase(&A, &hBytes)
	var publicKeyBytes [32]byte
	A.ToBytes(&publicKeyBytes)

	return publicKeyBytes
}

func (priv XPrv) EDPrivKey() ed25519.PrivKeyEd25519 {
	var hBytes [64]byte
	copy(hBytes[:], priv[:32])
	pubBytes := priv.EDPubKey()
	copy(hBytes[32:], pubBytes[:32])
	return hBytes
}

func (priv XPrv) String() string {
	return hex.EncodeToString(priv[:])
}
