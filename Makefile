# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
# Copyright (c) 2017-2021 Brett Sheffield <bacs@librecast.net>

export VERSION := 0.4.5
export ABIVERS := 0.4
PREFIX ?= /usr/local
export PREFIX
LIBNAME := librecast
LIBDIR := $(PREFIX)/lib
LIBFILE := lib${LIBNAME}.so
INCLUDEDIR := $(PREFIX)/include
COVERITY_DIR := cov-int
COVERITY_TGZ := $(LIBNAME).tgz
OSNAME := $(shell uname -s)
export OSNAME
ifndef USE_BLAKE3
USE_LIBSODIUM=1
export USE_LIBSODIUM
endif

all: src

install: all doc
	cd src && $(MAKE) $@

uninstall:
	cd src && $(MAKE) $@

.PHONY: clean realclean src test sparse doc libs

libs:
	$(MAKE) -C $@

src: libs
	$(MAKE) -C $@

doc:
	cd doc && $(MAKE) $@

fixme:
	grep -n FIXME src/*.{c,h} test/*.{c,h}

todo:
	grep -n TODO src/*.{c,h} test/*.{c,h}

clean realclean:
	cd src && $(MAKE) $@
	cd test && $(MAKE) $@
	cd libs && $(MAKE) $@
	rm -rf ./$(COVERITY_DIR)
	rm -f $(COVERITY_TGZ)

sparse: clean
	CC=cgcc $(MAKE) src

clang: clean
	CC=clang $(MAKE) src

clangtest: clean
	CC=clang $(MAKE) test

gcc: clean all

check test sanitize: clean src
	cd test && $(MAKE) $@

%.test %.check %.debug: src
	cd test && $(MAKE) $@

coverity: clean
	PATH=$(PATH):../cov-analysis-linux64-2019.03/bin/ cov-build --dir cov-int $(MAKE) src
	tar czvf $(COVERITY_TGZ) $(COVERITY_DIR)
