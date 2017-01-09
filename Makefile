all: src tests

.PHONY: clean src tests

src:
	cd src && make
tests:
	cd tests && make

clean:
	cd src && make clean
	cd tests && make clean
