# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2017-2021 Brett Sheffield <bacs@librecast.net>

PREFIX ?= /usr/local
export PREFIX
LIBNAME := librecast
LIBDIR := $(PREFIX)/lib
LIBFILE := lib${LIBNAME}.so
INCLUDEDIR := $(PREFIX)/include
COVERITY_DIR := cov-int
COVERITY_TGZ := $(LIBNAME).tgz

all: src

install: all doc
	cd src && $(MAKE) $@

uninstall:
	cd src && $(MAKE) $@

.PHONY: clean realclean src test sparse doc

src:
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

%.test %.check %.debug:
	cd test && $(MAKE) -B $@

coverity: clean
	PATH=$(PATH):../cov-analysis-linux64-2019.03/bin/ cov-build --dir cov-int $(MAKE) src
	tar czvf $(COVERITY_TGZ) $(COVERITY_DIR)
