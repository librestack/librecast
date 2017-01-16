CC=gcc
CCOPTS=-Wall -Werror -g
BUILD_TESTS= \
	build_test_librecast_running_false \
	build_test_librecast_running_true
DOCKER_TESTS= \
	test_librecast_running
LIBPATH=/usr/local/lib
DOCKERBIN=docker/librecastd/bin
LIBS=-llibrecast -L${LIBPATH} -Wl,-rpath=${LIBPATH}

build_all: ${BUILD_TESTS}

build_test_librecast_running_false: test_librecast_running_false.c
	${CC} ${CCOPTS} test_librecast_running_false.c -o ${DOCKERBIN}/test_librecast_running_false ${LIBS}

build_test_librecast_running_true: test_librecast_running_true.c
	${CC} ${CCOPTS} test_librecast_running_true.c -o ${DOCKERBIN}/test_librecast_running_true ${LIBS}

.PHONY: clean run_tests

clean:
	rm -f *.o ${BUILD_TESTS}

run_all:
	docker run librecastd:stopped test_librecast_running_false
	docker run librecastd:running test_librecast_running_true
