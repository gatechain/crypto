# Crypto

This repository is the cryptographic package adapted for GateChain's uses.

## Download/Install

The easiest way to install is to run `go get -u github.com/gatechain/crypto`. You can also manually git clone the repository to `$GOPATH/src/github.com/gatechain/crypto`.

## Usage

```
import "github.com/gatechain/crypto"
```

This package depends on [libsodium](https://github.com/jedisct1/libsodium). Set the following environment variables before using

```
export SODIUM_PATH=/usr/local  (The installed libsodium library path, Users modify the installation path according to their own)
export CGO_CFLAGS="-I$SODIUM_PATH/include"
export CGO_LDFLAGS="-L$SODIUM_PATH/lib"
```

## Report Issues / Send Patches

The main issue tracker for the repository is located at https://github.com/gatechain/crypto/issues. 

Note that contributions to the cryptography package receive additional scrutiny due to their sensitive nature. Patches may take longer than normal to receive feedback.

