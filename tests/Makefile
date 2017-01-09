CC=gcc
CCOPTS=-Wall -Werror -g
ALL_TESTS=test_librecast_running

all: ${ALL_TESTS}
	./test_librecast_running

test_librecast_running: test_librecast_running.c
	${CC} ${CCOPTS} test_librecast_running.c -o test_librecast_running


.PHONY: clean

clean:
	rm -f *.o
	rm ${ALL_TESTS}
