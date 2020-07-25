CFLAGS += -Wall -L../src
LIBS = -llibrecast
PASS = "\\e[0m\\e[32m" # end bold, green text
FAIL = "\\e[0m\\e[31m" # end bold, red text
LOGFILE := $(shell mktemp "lsdb-test-XXXXXXXX.log")
TIMESTAMP = $(shell date +"%Y-%m-%d %H:%M:%S")

.PHONY: test clean realclean build result memcheck

memcheck: MEMCHECK = valgrind --leak-check=full --error-exitcode=2 --errors-for-leak-kinds=all --log-file=$@.valgrind
memcheck: test

test: clean build $(shell echo ????-????.c | sed 's/\.c/\.test/g') result

build:
	cd ../src && $(MAKE)
	@echo -e "$(TIMESTAMP) - starting tests" >> $(LOGFILE)
	@echo -e "\nRunning tests"

%.test: %.c test.o
	@$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
	@echo -ne "\e[2m" $* " "
	@echo -ne "\n== $@" >> $(LOGFILE)
	@LD_LIBRARY_PATH=../src $(MEMCHECK) ./$@ 2>> $(LOGFILE) && echo -e " $(PASS)OK\e[0m" || echo -e " $(FAIL)FAIL\e[0m"
	@$(eval tests_run=$(shell echo $$(($(tests_run)+1))))

test.o: test.h

result:
	@echo -e "\n$(TIMESTAMP) - tests done" >> $(LOGFILE)
	@echo -e "$(tests_run) tests run\nlogfile: $(LOGFILE)\n"

clean:
	rm -f *.test *.o
	@rm -f $(LOGFILE)

realclean: clean
	rm -f lsdb-test-????????.log* ????-????.test.valgrind

