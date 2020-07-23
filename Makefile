INSTALLDIR=/usr/local/bin
LIBNAME=librecast
LIBDIR=/usr/local/lib
LIBFILE=lib${LIBNAME}.so
INCLUDEDIR=/usr/local/include

all: src

install: all
	cd src && $(MAKE) $@

.PHONY: clean src test

src:
	cd src && $(MAKE)
clean:
	cd src && $(MAKE) $@
	cd test && $(MAKE) $@
memcheck:
	cd test && $(MAKE) $@
test:
	cd test && $(MAKE) $@
