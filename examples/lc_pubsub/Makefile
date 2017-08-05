CFLAGS += -Wall -Werror -g
LIBS += -llibrecast

.PHONY: all
all: publish subscribe

publish: publish.o
	$(CC) $(LDFLAGS) -o publish publish.o $(LIBS)

subscribe: subscribe.o
	$(CC) $(LDFLAGS) -o subscribe subscribe.o $(LIBS)

publish.o: publish.c
	$(CC) $(CFLAGS) -c publish.c $(LIBS)

subscribe.o: subscribe.c
	$(CC) $(CFLAGS) -c subscribe.c $(LIBS)

.PHONY: clean
clean:
	rm -f *.o

.PHONY: distclean
distclean: clean
	rm -f publish subscribe
