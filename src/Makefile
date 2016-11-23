CC=gcc
CCOPTS=-Wall -Werror -g
PROGRAM=librecast
DAEMON=${PROGRAM}d
CLIENT=${PROGRAM}ctl
DAEMON_OBJECTS=daemon.o args.o config.o controller.o errors.o log.o misc.o signals.o
CLIENT_OBJECTS=client.o args.o config.o controller.o errors.o log.o misc.o signals.o

${DAEMON}: ${DAEMON_OBJECTS}
	${CC} ${CCOPTS} -o ${DAEMON} ${DAEMON_OBJECTS}

${CLIENT}: ${CLIENT_OBJECTS}
	${CC} ${CCOPTS} -o ${CLIENT} ${CLIENT_OBJECTS}

client.o: client.h client.c
	${CC} ${CCOPTS} -c client.c

daemon.o: daemon.h daemon.c
	${CC} ${CCOPTS} -c daemon.c

args.o: args.h args.c
	${CC} ${CCOPTS} -c args.c

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
	rm -f *.o ${DAEMON} ${CLIENT}

leakcheck: ${DAEMON}
	make clean && make && valgrind -v ./${DAEMON}
