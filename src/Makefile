CC=gcc
CCOPTS=-Wall -Werror -g
PROGRAM=librecastd
OBJECTS=main.o debug.o errors.o misc.o signals.o

${PROGRAM}: ${OBJECTS}
	${CC} ${CCOPTS} -o ${PROGRAM} ${OBJECTS}

main.o: main.h main.c
	${CC} ${CCOPTS} -c main.c

debug.o: debug.h debug.c
	${CC} ${CCOPTS} -c debug.c

errors.o: errors.h errors.c
	${CC} ${CCOPTS} -c errors.c

misc.o: misc.h misc.c
	${CC} ${CCOPTS} -c misc.c

signals.o: signals.h signals.c
	${CC} ${CCOPTS} -c signals.c

.PHONY: clean

clean:
	rm -f *.o ${PROGRAM}
