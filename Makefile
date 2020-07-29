INSTALLDIR=/usr/local/bin
LIBNAME=librecast
LIBDIR=/usr/local/lib
LIBFILE=lib${LIBNAME}.so
INCLUDEDIR=/usr/local/include

all: src

install: all
	cd src && $(MAKE) $@

uninstall:
	cd src && $(MAKE) $@

.PHONY: clean realclean src test sparse

src:
	cd src && $(MAKE)
clean realclean:
	cd src && $(MAKE) $@
	cd test && $(MAKE) $@
sparse: clean
	CC=cgcc $(MAKE) src
clang: clean
	CC=clang $(MAKE) src
check:
	cd test && $(MAKE) $@
test:
	cd test && $(MAKE) $@
%.test %.check %.debug:
	cd test && $(MAKE) -B $@
