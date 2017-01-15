CC=gcc
CCOPTS=-Wall -Werror -g
ALL_TESTS= \
	test_pass \
	test_fail
LIBPATH=../src
LIBS=-llibrecast -L${LIBPATH} -Wl,-rpath=${LIBPATH}

all: ${ALL_TESTS}
	./test_librecast_running

#test_librecast_running: test_librecast_running.c
#	${CC} ${CCOPTS} test_librecast_running.c -o test_librecast_running ${LIBS}

test_pass: docker/librecastd/Dockerfile
	docker run librecastd /bin/true

test_fail: docker/librecastd/Dockerfile
	docker run librecastd /bin/false

.PHONY: clean

clean:
	rm -f *.o
