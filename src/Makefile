CFLAGS += -Wall -Werror -g -I ../include
HEADERS = ../include/$(LIBNAME).h ../include/$(LIBNAME)/*.h
LIBNAME = librecast
INSTALLDIR = /usr/local/bin
LIBDIR = /usr/local/lib
LIBFILE = lib$(LIBNAME).so
INCLUDEDIR = /usr/local/include
LIBS = -pthread -lpthread -lbridge -lcrypto -llmdb
OBJECTS = $(LIBNAME).o errors.o log.o misc.o

all: $(LIBFILE)

$(LIBFILE): $(OBJECTS)
	$(CC) $(CFLAGS) -shared -o $(LIBFILE) $(OBJECTS) $(LIBS)

$(LIBNAME).o: $(LIBNAME).c $(HEADERS)
	$(CC) $(CFLAGS) -fPIC -c $< $(LIBS)

errors.o: errors.h
	$(CC) $(CFLAGS) -fPIC -c errors.c $(LIBS)

log.o: log.h
	$(CC) $(CFLAGS) -fPIC -c log.c $(LIBS)

misc.o: misc.h
	$(CC) $(CFLAGS) -fPIC -c misc.c $(LIBS)

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
	$(RM) *.o $(LIBFILE)

realclean: clean
