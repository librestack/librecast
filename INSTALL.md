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

## Using libsodium

It is possible to use libsodium (BLAKE2B) for hashing instead of the included
default BLAKE3 if desired.  BLAKE3 is faster and has similar characteristics to
BLAKE2B.

To use libsodium, build with:

`USE_LIBSODIUM=1 make`

### Install libsodium on Ubuntu (optional)

`sudo apt install libsodium-dev`
