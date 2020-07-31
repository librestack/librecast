# INSTALL

## Prerequisites

libbridge from bridge-utils

```
I've turned this into a shared library.  Install as follows:
git clone https://github.com/brettsheffield/bridge-utils
cd bridge-utils
autoconf
./configure --prefix=/ --libdir=/usr/lib6 --includedir=/usr/include --with-linux-headers=/usr/include
cd libbridge
make
make install
```

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

