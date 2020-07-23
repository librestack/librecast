CFLAGS += -L../src
LIBS = -llibrecast
PASS = "\\e[0m\\e[32m" # end bold, green text
FAIL = "\\e[0m\\e[31m" # end bold, red text

.PHONY: test clean build result memcheck

memcheck: MEMCHECK = valgrind -q --leak-check=full --error-exitcode=2 --errors-for-leak-kinds=all

memcheck: test

test: clean build $(shell echo ????-????.c | sed 's/\.c/\.test/g') result

build:
	cd ../src && $(MAKE)

%.test: %.c test.o
	@$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
	@echo -ne "\e[2m" $* " "
	@LD_LIBRARY_PATH=../src $(MEMCHECK) ./$@ 2> /dev/null && echo -e " $(PASS)OK\e[0m" || echo -e " $(FAIL)FAIL\e[0m"
	@$(eval tests_run=$(shell echo $$(($(tests_run)+1))))

test.o: test.h

result:
	@echo $(tests_run) tests run

clean:
	rm -f *.test *.o
