# INSTALL

## Prerequisites

* libsodium

### Install libsodium on Ubuntu

`sudo apt-install libsodium-dev


## Installing from source

The code compiles using either gcc or clang.  There is a `make clang` target to
force compilation with clang.  The default is whatever your default CC is set
to.

Download the source:

`git clone https://github.com/librestack/librecast.git`

then, do the usual:
```
cd librecast
make
make install
```

To install to a different location:

`DESTDIR=/tmp make install`

