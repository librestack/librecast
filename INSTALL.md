# INSTALL

## Prerequisites

None.

## Installing from source

The code compiles using either gcc or clang.  There is a `make clang` target to
force compilation with clang.  The default is whatever your default CC is set
to.

Download the source:

`git clone --recursive https://github.com/librestack/librecast.git`

then, do the usual:
```
cd librecast
make
make install
```

To install to a different location:

`DESTDIR=/tmp make install`

## Hashing with BLAKE3 instead of libsodium (BLAKE2B)

By default librecast uses BLAKE2B from libsodium for hashing.  If you want to
use BLAKE3 instead, ensure you did a recursive clone to obtain the blake3
sources and build with:

`make USE_BLAKE3=1`

### Install libsodium on Ubuntu (unless using BLAKE3)

`sudo apt install libsodium-dev`
