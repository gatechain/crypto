package crypto

import (
	"crypto/sha256"
)

// HashID is a domain separation prefix for an object type that might be hashed
// This ensures, for example, the hash of a transaction will never collide with the hash of a vote
type HashID string

func Sha256(bytes []byte) []byte {
	hasher := sha256.New()
	hasher.Write(bytes)
	return hasher.Sum(nil)
}
