INSTALLDIR=/usr/local/bin
LIBNAME=librecast
LIBDIR=/usr/local/lib
LIBFILE=lib${LIBNAME}.so
INCLUDEDIR=/usr/local/include
DOCKERFILES= \
	tests/docker/librecastd/Dockerfile.stopped \
	tests/docker/librecastd/Dockerfile.running

all: src tests docker run_tests

install: all
	cp src/librecastd ${INSTALLDIR}
	cp src/${LIBFILE} ${LIBDIR}/${LIBFILE}.1.0
	ln -sf ${LIBDIR}/${LIBFILE}.1.0 ${LIBDIR}/${LIBFILE}.1
	ln -sf ${LIBDIR}/${LIBFILE}.1 ${LIBDIR}/${LIBFILE}
	cp src/${LIBNAME}.h ${INCLUDEDIR}
	cp src/lctl ${INSTALLDIR}
	cp src/nodewatch ${INSTALLDIR}

docker: ${DOCKERFILES}
	docker build -t librecastd:stopped -f tests/docker/librecastd/Dockerfile.stopped .
	docker build -t librecastd:running -f tests/docker/librecastd/Dockerfile.running .

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
