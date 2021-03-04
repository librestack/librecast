# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2017-2021 Brett Sheffield <bacs@librecast.net>

VERSION := 0.4.0
ABIVERS := 0.4
SHELL = /bin/sh
.SUFFIXES:
.SUFFIXES: .c .o
CFLAGS += -Wall -Wextra -Wpedantic -g -I ../include
HEADERS = ../include/$(LIBNAME).h $(wildcard ../include/$(LIBNAME)/*.h)
LIBNAME := librecast
INSTALL ?= install
LDCONFIG ?= ldconfig
INSTALL_DATA := $(INSTALL) -m 644
PREFIX ?= /usr/local
LIBDIR := $(DESTDIR)$(PREFIX)/lib
INCLUDEDIR := $(DESTDIR)$(PREFIX)/include
LIBS := -pthread -lpthread -lsodium
OBJECTS := errors.o hash.o
SOFILES := liblibrecast.so
SOVFILES := $(foreach f,$(SOFILES),$f.$(VERSION))
ABIFILES := $(foreach f,$(SOFILES),$f.$(ABIVERS))

all: $(SOFILES)

liblibrecast.so: librecast.o $(OBJECTS)
	$(CC) -shared -Wl,-soname,liblibrecast.so.$(ABIVERS) -o $@ $^ $(LIBS)

%.o: %.c %.h librecast_pvt.h $(HEADERS)
	$(CC) $(CFLAGS) -fPIC -c $<

%.o: %.c librecast_pvt.h
	$(CC) $(CFLAGS) -fPIC -c $<

install: $(SOFILES)
	$(INSTALL) -d $(LIBDIR)
	$(INSTALL) -d $(INCLUDEDIR)
	$(INSTALL_DATA) liblibrecast.so $(LIBDIR)/liblibrecast.so.$(VERSION)
	cp -r ../include/* $(INCLUDEDIR)
	$(LDCONFIG)
	ln -sf $(LIBDIR)/liblibrecast.so.$(ABIVERS) $(LIBDIR)/liblibrecast.so

.PHONY: clean realclean uninstall

uninstall:
	rm -f $(foreach f,$(SOFILES),$(DESTDIR)$(LIBDIR)/$f.$(VERSION))
	$(LDCONFIG) -n $(LIBDIR)
	cd $(LIBDIR)/ && rm -f $(SOFILES)

clean:
	$(RM) *.o $(SOFILES) $(ABIFILES)

realclean: clean
