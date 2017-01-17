INSTALLDIR=/usr/local/bin
LIBNAME=librecast
LIBDIR=/usr/local/lib
LIBFILE=lib${LIBNAME}.so
INCLUDEDIR=/usr/local/include
#DOCKERFILES= \
#	tests/docker/librecastd/Dockerfile.stopped \
#	tests/docker/librecastd/Dockerfile.running

all: src run_tests

install: all
	cd src && make install

docker0: tests/docker/librecastd/Dockerfile
	docker build -t librecastd -f tests/docker/librecastd/Dockerfile .

#docker: ${DOCKERFILES}
#	docker build -t librecastd:stopped -f tests/docker/librecastd/Dockerfile.stopped .
#	docker build -t librecastd:running -f tests/docker/librecastd/Dockerfile.running .

.PHONY: clean src tests

src:
	cd src && make
tests:
	cd tests && make

run_tests:
	cd tests && make run_all

clean:
	cd src && make clean
	cd tests && make clean
