CC=gcc
CCOPTS=-Wall -Werror -g
PROGRAM=librecastd
OBJECTS=main.o

${PROGRAM}: ${OBJECTS}
	${CC} ${CCOPTS} -o ${PROGRAM} main.o

main.o: main.h main.c
	${CC} ${CCOPTS} -c main.c

.PHONY: clean

clean:
	rm -f *.o ${PROGRAM}
