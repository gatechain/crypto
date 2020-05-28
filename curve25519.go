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

// #cgo CFLAGS: -Wall -std=c99
// #cgo LDFLAGS: -lsodium
// #include <stdint.h>
// #include "sodium.h"
import "C"

import (
	"fmt"
	"github.com/gatechain/crypto/metrics"
)

// TODO: Remove metrics from crypto package
var cryptoVRFGenerateTotal = metrics.MakeCounter(metrics.CryptoVRFGenerateTotal)
var cryptoVRFProveTotal = metrics.MakeCounter(metrics.CryptoVRFProveTotal)
var cryptoVRFHashTotal = metrics.MakeCounter(metrics.CryptoVRFHashTotal)
var cryptoVRFVerifyTotal = metrics.MakeCounter(metrics.CryptoVRFVerifyTotal)
var cryptoGenSigSecretsTotal = metrics.MakeCounter(metrics.CryptoGenSigSecretsTotal)
var cryptoSigSecretsSignTotal = metrics.MakeCounter(metrics.CryptoSigSecretsSignTotal)
var cryptoSigSecretsSignBytesTotal = metrics.MakeCounter(metrics.CryptoSigSecretsSignBytesTotal)
var cryptoSigSecretsVerifyTotal = metrics.MakeCounter(metrics.CryptoSigSecretsVerifyTotal)
var cryptoSigSecretsVerifyBytesTotal = metrics.MakeCounter(metrics.CryptoSigSecretsVerifyBytesTotal)

const masterDerivationKeyLenBytes = 32

func init() {
	if C.sodium_init() < 0 {
		//logging.Init()
		//logging.Base().Fatal("failed to initialize libsodium!")
	}
}

// A Seed holds the entropy needed to generate cryptographic keys.
type Seed Ed25519Seed

/* Classical signatures */

type Ed25519Signature [C.crypto_sign_ed25519_BYTES]byte
type Ed25519PublicKey [C.crypto_sign_ed25519_PUBLICKEYBYTES]byte
type Ed25519PrivateKey [C.crypto_sign_ed25519_SECRETKEYBYTES]byte
type Ed25519Seed [C.crypto_sign_ed25519_SEEDBYTES]byte

// MasterDerivationKey is used to derive ed25519 keys for use in wallets
type MasterDerivationKey [masterDerivationKeyLenBytes]byte

// PrivateKey is an exported Ed25519PrivateKey
type PrivateKey Ed25519PrivateKey

// PublicKey is an exported Ed25519PublicKey
type PublicKey Ed25519PublicKey

func Ed25519GenerateKey() (public Ed25519PublicKey, secret Ed25519PrivateKey) {
	var seed Ed25519Seed
	RandBytes(seed[:])
	return Ed25519GenerateKeySeed(seed)
}

func Ed25519GenerateKeyRNG(rng RNG) (public Ed25519PublicKey, secret Ed25519PrivateKey) {
	var seed Ed25519Seed
	rng.RandBytes(seed[:])
	return Ed25519GenerateKeySeed(seed)
}

func Ed25519GenerateKeySeed(seed Ed25519Seed) (public Ed25519PublicKey, secret Ed25519PrivateKey) {
	C.crypto_sign_ed25519_seed_keypair((*C.uchar)(&public[0]), (*C.uchar)(&secret[0]), (*C.uchar)(&seed[0]))
	return
}

func Ed25519Sign(secret Ed25519PrivateKey, data []byte) (sig Ed25519Signature) {
	// &data[0] will make Go panic if msg is zero length
	d := (*C.uchar)(C.NULL)
	if len(data) != 0 {
		d = (*C.uchar)(&data[0])
	}
	// https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures#detached-mode
	C.crypto_sign_ed25519_detached((*C.uchar)(&sig[0]), (*C.ulonglong)(C.NULL), d, C.ulonglong(len(data)), (*C.uchar)(&secret[0]))
	return
}

func Ed25519Verify(public Ed25519PublicKey, data []byte, sig Ed25519Signature) bool {
	// &data[0] will make Go panic if msg is zero length
	d := (*C.uchar)(C.NULL)
	if len(data) != 0 {
		d = (*C.uchar)(&data[0])
	}
	// https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures#detached-mode
	result := C.crypto_sign_ed25519_verify_detached((*C.uchar)(&sig[0]), d, C.ulonglong(len(data)), (*C.uchar)(&public[0]))
	return result == 0
}

// A Signature is a cryptographic signature. It proves that a message was
// produced by a holder of a cryptographic secret.
type Signature Ed25519Signature

// A SignatureVerifier is used to identify the holder of SignatureSecrets
// and verify the authenticity of Signatures.
type SignatureVerifier = PublicKey

// SignatureSecrets are used by an entity to produce unforgeable signatures over
// a message.
type SignatureSecrets struct {
	SignatureVerifier
	SK Ed25519PrivateKey
}

// SecretKeyToSignatureSecrets converts a private key into a SignatureSecrets and
// returns a pointer
func SecretKeyToSignatureSecrets(sk PrivateKey) (secrets *SignatureSecrets, err error) {
	pk, err := SecretKeyToPublicKey(sk)
	if err != nil {
		return
	}
	secrets = &SignatureSecrets{
		SignatureVerifier: SignatureVerifier(pk),
		SK:                Ed25519PrivateKey(sk),
	}
	return
}

// SecretKeyToPublicKey derives a public key from a secret key. This is very
// efficient since ed25519 private keys literally contain their public key
func SecretKeyToPublicKey(secret PrivateKey) (PublicKey, error) {
	var pk PublicKey
	result := C.crypto_sign_ed25519_sk_to_pk((*C.uchar)(&pk[0]), (*C.uchar)(&secret[0]))
	if result != 0 {
		return pk, fmt.Errorf("failed to extract public key: %d", result)
	}
	return pk, nil
}

// SecretKeyToSeed derives the seed from a secret key. This is very efficient
// since ed25519 private keys literally contain their seed
func SecretKeyToSeed(secret PrivateKey) (Seed, error) {
	var seed Seed
	result := C.crypto_sign_ed25519_sk_to_seed((*C.uchar)(&seed[0]), (*C.uchar)(&secret[0]))
	if result != 0 {
		return seed, fmt.Errorf("failed to extract seed: %d", result)
	}
	return seed, nil
}

// GenerateSignatureSecrets creates SignatureSecrets from a source of entropy.
func GenerateSignatureSecrets(seed Seed) *SignatureSecrets {
	pk0, sk := Ed25519GenerateKeySeed(Ed25519Seed(seed))
	pk := SignatureVerifier(pk0)
	cryptoGenSigSecretsTotal.Inc(map[string]string{})
	return &SignatureSecrets{SignatureVerifier: pk, SK: sk}
}

// Sign produces a cryptographic Signature of a Hashable message, given
// cryptographic secrets.
func (s *SignatureSecrets) Sign(message Hashable) Signature {
	cryptoSigSecretsSignTotal.Inc(map[string]string{})
	return s.SignBytes(HashRep(message))
}

// SignBytes signs a message directly, without first hashing.
// Caller is responsible for domain separation.
func (s *SignatureSecrets) SignBytes(message []byte) Signature {
	cryptoSigSecretsSignBytesTotal.Inc(map[string]string{})
	return Signature(Ed25519Sign(Ed25519PrivateKey(s.SK), message))
}

// Verify verifies that some holder of a cryptographic secret authentically
// signed a Hashable message.
//
// It returns true if this is the case; otherwise, it returns false.
//
func (v SignatureVerifier) Verify(message Hashable, sig Signature) bool {
	cryptoSigSecretsVerifyTotal.Inc(map[string]string{})
	return Ed25519Verify(Ed25519PublicKey(v), HashRep(message), Ed25519Signature(sig))
}

// VerifyBytes verifies a signature, where the message is not hashed first.
// Caller is responsible for domain separation.
// If the message is a Hashable, Verify() can be used instead.
func (v SignatureVerifier) VerifyBytes(message []byte, sig Signature) bool {
	cryptoSigSecretsVerifyBytesTotal.Inc(map[string]string{})
	return Ed25519Verify(Ed25519PublicKey(v), message, Ed25519Signature(sig))
}
