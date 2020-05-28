package cryptoamino

import (
	"github.com/gatechain/crypto/ed25519x"
	"reflect"

	"github.com/gatechain/crypto"
	"github.com/gatechain/crypto/ed25519"
	"github.com/gatechain/crypto/multisig"
	"github.com/gatechain/crypto/secp256k1"
	"github.com/gatechain/crypto/sr25519"
	amino "github.com/tendermint/go-amino"
)

var cdc = amino.NewCodec()

// nameTable is used to map public key concrete types back
// to their registered amino names. This should eventually be handled
// by amino. Example usage:
// nameTable[reflect.TypeOf(ed25519.PubKeyEd25519{})] = ed25519.PubKeyAminoName
var nameTable = make(map[reflect.Type]string, 3)

func init() {
	RegisterAmino(cdc)

	// TODO: Have amino provide a way to go from concrete struct to route directly.
	// Its currently a private API
	nameTable[reflect.TypeOf(ed25519.PubKeyEd25519{})] = ed25519.PubKeyAminoName
	nameTable[reflect.TypeOf(sr25519.PubKeySr25519{})] = sr25519.PubKeyAminoName
	nameTable[reflect.TypeOf(secp256k1.PubKeySecp256k1{})] = secp256k1.PubKeyAminoName
	nameTable[reflect.TypeOf(multisig.PubKeyMultisigThreshold{})] = multisig.PubKeyMultisigThresholdAminoRoute
}

// PubkeyAminoName returns the amino route of a pubkey
// cdc is currently passed in, as eventually this will not be using
// a package level codec.
func PubkeyAminoName(cdc *amino.Codec, key crypto.PubKey) (string, bool) {
	route, found := nameTable[reflect.TypeOf(key)]
	return route, found
}

// RegisterAmino registers all crypto related types in the given (amino) codec.
func RegisterAmino(cdc *amino.Codec) {
	// These are all written here instead of
	cdc.RegisterInterface((*crypto.PubKey)(nil), nil)
	cdc.RegisterConcrete(ed25519.PubKeyEd25519{},
		ed25519.PubKeyAminoName, nil)
	cdc.RegisterConcrete(sr25519.PubKeySr25519{},
		sr25519.PubKeyAminoName, nil)
	cdc.RegisterConcrete(secp256k1.PubKeySecp256k1{},
		secp256k1.PubKeyAminoName, nil)
	cdc.RegisterConcrete(multisig.PubKeyMultisigThreshold{},
		multisig.PubKeyMultisigThresholdAminoRoute, nil)
	cdc.RegisterConcrete(ed25519x.XPub{}, ed25519x.XPubKeyAminoName, nil)

	cdc.RegisterInterface((*crypto.PrivKey)(nil), nil)
	cdc.RegisterConcrete(ed25519.PrivKeyEd25519{},
		ed25519.PrivKeyAminoName, nil)
	cdc.RegisterConcrete(sr25519.PrivKeySr25519{},
		sr25519.PrivKeyAminoName, nil)
	cdc.RegisterConcrete(secp256k1.PrivKeySecp256k1{},
		secp256k1.PrivKeyAminoName, nil)
	cdc.RegisterConcrete(ed25519x.XPrv{}, ed25519x.XPrivKeyAminoName, nil)
}

// RegisterKeyType registers an external key type to allow decoding it from bytes
func RegisterKeyType(o interface{}, name string) {
	cdc.RegisterConcrete(o, name, nil)
	nameTable[reflect.TypeOf(o)] = name
}

// PrivKeyFromBytes unmarshals private key bytes and returns a PrivKey
func PrivKeyFromBytes(privKeyBytes []byte) (privKey crypto.PrivKey, err error) {
	err = cdc.UnmarshalBinaryBare(privKeyBytes, &privKey)
	return
}

// PubKeyFromBytes unmarshals public key bytes and returns a PubKey
func PubKeyFromBytes(pubKeyBytes []byte) (pubKey crypto.PubKey, err error) {
	err = cdc.UnmarshalBinaryBare(pubKeyBytes, &pubKey)
	return
}
