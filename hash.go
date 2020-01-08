package crypto

import (
	"crypto/sha256"
	"crypto/sha512"
)

func Sha256(bytes []byte) []byte {
	hasher := sha256.New()
	hasher.Write(bytes)
	return hasher.Sum(nil)
}

func Sha512(bytes []byte) []byte {
	hasher := sha512.New()
	hasher.Write(bytes)
	return hasher.Sum(nil)
}