package tmhash

import (
	"crypto/sha512"
	"hash"
)

const (
	Size      = sha512.Size
	BlockSize = sha512.BlockSize
)

// New returns a new hash.Hash.
func New() hash.Hash {
	return sha512.New()
}

// Sum returns the SHA256 of the bz.
func Sum(bz []byte) []byte {
	h := sha512.Sum512(bz)
	return h[:]
}

//-------------------------------------------------------------

const (
	TruncatedSize = 20
)

type sha512trunc struct {
	sha512 hash.Hash
}

func (h sha512trunc) Write(p []byte) (n int, err error) {
	return h.sha512.Write(p)
}
func (h sha512trunc) Sum(b []byte) []byte {
	shasum := h.sha512.Sum(b)
	return shasum[:TruncatedSize]
}

func (h sha512trunc) Reset() {
	h.sha512.Reset()
}

func (h sha512trunc) Size() int {
	return TruncatedSize
}

func (h sha512trunc) BlockSize() int {
	return h.sha512.BlockSize()
}

// NewTruncated returns a new hash.Hash.
func NewTruncated() hash.Hash {
	return sha512trunc{
		sha512: sha512.New(),
	}
}

// SumTruncated returns the first 20 bytes of SHA256 of the bz.
func SumTruncated(bz []byte) []byte {
	hash := sha512.Sum512(bz)
	return hash[:TruncatedSize]
}
