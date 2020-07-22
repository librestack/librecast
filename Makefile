INSTALLDIR=/usr/local/bin
LIBNAME=librecast
LIBDIR=/usr/local/lib
LIBFILE=lib${LIBNAME}.so
INCLUDEDIR=/usr/local/include

all: src

install: all
	cd src && $(MAKE) install

.PHONY: clean src test

src:
	cd src && $(MAKE)
clean:
	cd src && $(MAKE) clean
test:
	cd test && $(MAKE) test
