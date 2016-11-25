CC=gcc
CCOPTS=-Wall -Werror -g
PROGRAM=librecast
DAEMON=${PROGRAM}d
CLIENT=${PROGRAM}ctl
LIBS=-pthread
DAEMON_OBJECTS=daemon.o args.o config.o controller.o errors.o log.o misc.o net.o pid.o signals.o
CLIENT_OBJECTS=client.o args.o config.o errors.o log.o misc.o pid.o

all: ${DAEMON} ${CLIENT}

${DAEMON}: ${DAEMON_OBJECTS}
	${CC} ${CCOPTS} -o ${DAEMON} ${DAEMON_OBJECTS} ${LIBS}

${CLIENT}: ${CLIENT_OBJECTS}
	${CC} ${CCOPTS} -o ${CLIENT} ${CLIENT_OBJECTS} ${LIBS}

client.o: main.h client.c
	${CC} ${CCOPTS} -c client.c ${LIBS}

daemon.o: main.h daemon.c
	${CC} ${CCOPTS} -c daemon.c ${LIBS}

args.o: args.h args.c
	${CC} ${CCOPTS} -c args.c ${LIBS}

config.o: config.h config.c
	${CC} ${CCOPTS} -c config.c ${LIBS}

controller.o: controller.h controller.c
	${CC} ${CCOPTS} -c controller.c ${LIBS}

errors.o: errors.h errors.c
	${CC} ${CCOPTS} -c errors.c ${LIBS}

log.o: log.h log.c
	${CC} ${CCOPTS} -c log.c ${LIBS}

misc.o: misc.h misc.c
	${CC} ${CCOPTS} -c misc.c ${LIBS}

net.o: net.h net.c
	${CC} ${CCOPTS} -c net.c ${LIBS}

pid.o: pid.h pid.c
	${CC} ${CCOPTS} -c pid.c ${LIBS}

signals.o: signals.h signals.c
	${CC} ${CCOPTS} -c signals.c ${LIBS}

.PHONY: clean leakcheck

clean:
	rm -f *.o ${DAEMON} ${CLIENT}

leakcheck: ${DAEMON}
	make clean && make && valgrind -v ./${DAEMON}
