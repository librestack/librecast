# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2017-2020 Brett Sheffield <bacs@librecast.net>

CFLAGS += -Wall -Werror -g -I ../include
HEADERS = ../include/$(LIBNAME).h $(wildcard ../include/$(LIBNAME)/*.h)
LIBNAME := librecast
INSTALLDIR := /usr/local/bin
LIBDIR := /usr/local/lib
INCLUDEDIR := /usr/local/include
LIBS := -pthread -lpthread -lbridge -lcrypto -llmdb
OBJECTS := errors.o log.o misc.o
SOFILES := liblibrecast.so liblcdb.so liblsdb.so

all: $(SOFILES)

liblibrecast.so: librecast.o $(OBJECTS)
	$(CC) $(CFLAGS) -shared -o $@ $^ $(LIBS)

liblcdb.so: netdb.o $(OBJECTS)
	$(CC) $(CFLAGS) -shared -o $@ $^ $(LIBS)

liblsdb.so: db.o $(OBJECTS)
	$(CC) $(CFLAGS) -shared -o $@ $^ -llmdb

%.o: %.c %.h librecast_pvt.h $(HEADERS)
	$(CC) $(CFLAGS) -fPIC -c $<

%.o: %.c librecast_pvt.h
	$(CC) $(CFLAGS) -fPIC -c $<

install: $(LIBFILE)
	cp $(LIBFILE) $(LIBDIR)/$(LIBFILE).1.0
	ln -sf $(LIBDIR)/$(LIBFILE).1.0 $(LIBDIR)/$(LIBFILE).1
	ln -sf $(LIBDIR)/$(LIBFILE).1 $(LIBDIR)/$(LIBFILE)
	cp -r ../include/* $(INCLUDEDIR)
	ldconfig

.PHONY: clean realclean uninstall

uninstall:
	rm -f $(LIBDIR)/$(LIBFILE)
	rm -f $(LIBDIR)/$(LIBFILE).1
	rm -f $(LIBDIR)/$(LIBFILE).1.0

clean:
	$(RM) *.o $(SOFILES)

realclean: clean
