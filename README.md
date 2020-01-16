# crypto

Depend on github.com/algorand/libsodium
```
instructions：
1. install libsodium
2. set environment variable
    export SODIUM_PATH=/usr/local  (The installed libsodium library path, Users modify the installation path according to their own)
    export CGO_CFLAGS="-I$SODIUM_PATH/include"
    export CGO_LDFLAGS="-L$SODIUM_PATH/lib"
```

