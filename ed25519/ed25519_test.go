package ed25519_test

import (
	"fmt"
	"testing"

	"github.com/gatechain/crypto"
	"github.com/gatechain/crypto/ed25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignAndValidateEd25519(t *testing.T) {

	for i := 0; i < 10000; i++ {
		privKey := ed25519.GenPrivKey()
		pubKey := privKey.PubKey()

		msg := crypto.CRandBytes(128)
		sig, err := privKey.Sign(msg)
		require.Nil(t, err)

		// Test the signature
		assert.True(t, pubKey.VerifyBytes(msg, sig))

		// Mutate the signature, just one bit.
		sig[7] ^= byte(0x01)

		assert.False(t, pubKey.VerifyBytes(msg, sig))

		if i%1000 == 0 {
			fmt.Println(pubKey.Address())
			fmt.Println(pubKey.Address512())
		}
	}

}
