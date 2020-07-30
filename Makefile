INSTALLDIR := /usr/local/bin
LIBNAME := librecast
LIBDIR := /usr/local/lib
LIBFILE := lib${LIBNAME}.so
INCLUDEDIR := /usr/local/include
COVERITY_DIR := cov-int
COVERITY_TGZ := $(LIBNAME).tgz

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
	rm -rf ./$(COVERITY_DIR)
	rm -f $(COVERITY_TGZ)
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
coverity: clean
	PATH=$(PATH):../cov-analysis-linux64-2019.03/bin/ cov-build --dir cov-int $(MAKE) src
	tar czvf $(COVERITY_TGZ) $(COVERITY_DIR)
