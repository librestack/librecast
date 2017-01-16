CC=gcc
CCOPTS=-Wall -Werror -g
BUILD_TESTS= \
	build_test_succeed
DOCKER_TESTS= \
	test_pass \
	test_succeed
LIBPATH=/usr/local/lib
DOCKERBIN=docker/librecastd/bin
LIBS=-llibrecast -L${LIBPATH} -Wl,-rpath=${LIBPATH}

build_all: ${BUILD_TESTS}

build_test_succeed: test_succeed.c
	${CC} ${CCOPTS} test_succeed.c -o ${DOCKERBIN}/test_succeed ${LIBS}

.PHONY: clean run_tests ${DOCKER_TESTS}

clean:
	rm -f *.o ${BUILD_TESTS}

run_all: ${DOCKER_TESTS}

test_succeed:
	docker run librecastd test_succeed

test_pass:
	docker run librecastd /bin/true

test_fail:
	docker run librecastd /bin/false

