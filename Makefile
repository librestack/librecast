INSTALLDIR=/usr/local/bin
LIBNAME=librecast
LIBDIR=/usr/local/lib
LIBFILE=lib${LIBNAME}.so
INCLUDEDIR=/usr/local/include

all: src

install: all
	cd src && make install

.PHONY: clean src

src:
	cd src && make
clean:
	cd src && make clean
