CC=gcc
CCOPTS=-Wall -Werror -g
PROGRAM=librecast
LIBRARY=liblibrecast.so
DAEMON=${PROGRAM}d
CLIENT=lctl
NODEWATCH=nodewatch
LIBS=-pthread -lncurses
COMMON_OBJECTS=args.o config.o errors.o log.o misc.o pid.o socket.o
DAEMON_OBJECTS=${COMMON_OBJECTS} daemon.o commands.o controller.o handler.o net.o signals.o
CLIENT_OBJECTS=${COMMON_OBJECTS} client.o
NODEWATCH_OBJECTS=${COMMON_OBJECTS} nodewatch.o commands.o controller.o handler.o net.o

all: ${DAEMON} ${CLIENT} ${NODEWATCH} ${LIBRARY}

${LIBRARY}: librecast.o
	${CC} ${CCOPTS} -shared -o ${LIBRARY} librecast.o

${DAEMON}: ${DAEMON_OBJECTS}
	${CC} ${CCOPTS} -o ${DAEMON} ${DAEMON_OBJECTS} ${LIBS}

${CLIENT}: ${CLIENT_OBJECTS}
	${CC} ${CCOPTS} -o ${CLIENT} ${CLIENT_OBJECTS} ${LIBS}

${NODEWATCH}: ${NODEWATCH_OBJECTS}
	${CC} ${CCOPTS} -o ${NODEWATCH} ${NODEWATCH_OBJECTS} ${LIBS}

librecast.o: librecast.h librecast.c
	${CC} ${CCOPTS} -fpic -c librecast.c ${LIBS}

client.o: main.h client.c
	${CC} ${CCOPTS} -c client.c ${LIBS}

daemon.o: main.h daemon.c
	${CC} ${CCOPTS} -c daemon.c ${LIBS}

args.o: args.h args.c
	${CC} ${CCOPTS} -c args.c ${LIBS}

commands.o: commands.h commands.c
	${CC} ${CCOPTS} -c commands.c ${LIBS}

config.o: config.h config.c
	${CC} ${CCOPTS} -c config.c ${LIBS}

controller.o: controller.h controller.c
	${CC} ${CCOPTS} -c controller.c ${LIBS}

errors.o: errors.h errors.c
	${CC} ${CCOPTS} -c errors.c ${LIBS}

handler.o: handler.h handler.c
	${CC} ${CCOPTS} -c handler.c ${LIBS}

log.o: log.h log.c
	${CC} ${CCOPTS} -c log.c ${LIBS}

misc.o: misc.h misc.c
	${CC} ${CCOPTS} -c misc.c ${LIBS}

net.o: net.h net.c
	${CC} ${CCOPTS} -c net.c ${LIBS}

nodewatch.o: nodewatch.h nodewatch.c
	${CC} ${CCOPTS} -c nodewatch.c ${LIBS}

pid.o: pid.h pid.c
	${CC} ${CCOPTS} -c pid.c ${LIBS}

signals.o: signals.h signals.c
	${CC} ${CCOPTS} -c signals.c ${LIBS}

socket.o: socket.h socket.c
	${CC} ${CCOPTS} -c socket.c ${LIBS}

.PHONY: clean leakcheck

clean:
	rm -f *.o ${DAEMON} ${CLIENT} ${NODEWATCH}

leakcheck: ${DAEMON}
	make clean && make && valgrind -v ./${DAEMON}
