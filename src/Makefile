CC=gcc
CCOPTS=-Wall -Werror -g
PROGRAM=librecastd
OBJECTS=main.o config.o controller.o errors.o log.o misc.o signals.o

${PROGRAM}: ${OBJECTS}
	${CC} ${CCOPTS} -o ${PROGRAM} ${OBJECTS}

main.o: main.h main.c
	${CC} ${CCOPTS} -c main.c

config.o: config.h config.c
	${CC} ${CCOPTS} -c config.c

controller.o: controller.h controller.c
	${CC} ${CCOPTS} -c controller.c

errors.o: errors.h errors.c
	${CC} ${CCOPTS} -c errors.c

log.o: log.h log.c
	${CC} ${CCOPTS} -c log.c

misc.o: misc.h misc.c
	${CC} ${CCOPTS} -c misc.c

signals.o: signals.h signals.c
	${CC} ${CCOPTS} -c signals.c

.PHONY: clean leakcheck

clean:
	rm -f *.o ${PROGRAM}

leakcheck: ${PROGRAM}
	make clean && make && valgrind -v ./${PROGRAM}
