CC=gcc
CCOPTS=-Wall -Werror -g
ALL_TESTS=test_librecast_running
LIBPATH=../src
LIBS=-llibrecast -L${LIBPATH} -Wl,-rpath=${LIBPATH}

all: ${ALL_TESTS}
	./test_librecast_running

test_librecast_running: test_librecast_running.c
	${CC} ${CCOPTS} test_librecast_running.c -o test_librecast_running ${LIBS}


.PHONY: clean

clean:
	rm -f *.o
	rm ${ALL_TESTS}
