CFLAGS += -Wall -Werror -g
LIBS += -llibrecast -lncurses -lpthread

.PHONY: all
all: lcchat

lcchat: lcchat.o
	$(CC) $(LDFLAGS) -o lcchat lcchat.o $(LIBS)

lcchat.o: lcchat.c
	$(CC) $(CFLAGS) -c lcchat.c $(LIBS)

.PHONY: clean
clean:
	rm -f *.o

.PHONY: distclean
distclean: clean
	rm -f lcchat
