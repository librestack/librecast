# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2017-2020 Brett Sheffield <bacs@librecast.net>

CFLAGS += -Wall -g -I ../include
LDFLAGS := -L../src -llibrecast -llcdb -llsdb
BOLD := "\\e[0m\\e[2m"
RESET := "\\e[0m"
PASS = "\\e[0m\\e[32mOK\\e[0m" # end bold, green text
FAIL = "\\e[0m\\e[31mFAIL\\e[0m" # end bold, red text
LEAK = "\\e[0m\\e[31mFAIL \| LEAK\\e[0m\\n\\tSee $@.valgrind"
LOGFILE := $(shell mktemp "lsdb-test-XXXXXXXX.log")
TIMESTAMP = $(shell date +"%Y-%m-%d %H:%M:%S")
VALGRIND = valgrind --leak-check=full --error-exitcode=2 --errors-for-leak-kinds=all --log-file=$@.valgrind

.PHONY: test clean realclean build result check

check: MEMCHECK = $(VALGRIND)
check: FAIL = $(LEAK)
check: test

test: clean build $(shell echo ????-????.c | sed 's/\.c/\.test/g') result

build:
	cd ../src && $(MAKE)
	@echo -e "$(TIMESTAMP) - starting tests" >> $(LOGFILE)
	@echo -e "\nRunning tests"

%.test: %.c test.o ../src/liblibrecast.so
	@$(CC) $(CFLAGS) -o $@ $< test.o $(LDFLAGS)
	@echo -ne "\e[2m" $* " "
	@echo -ne "\n== $@" >> $(LOGFILE)
	@LD_LIBRARY_PATH=../src $(MEMCHECK) ./$@ 2>> $(LOGFILE) && echo -e " $(PASS)" || echo -e " $(FAIL)"
	@$(eval tests_run=$(shell echo $$(($(tests_run)+1))))

%.check: MEMCHECK = $(VALGRIND)
%.check: FAIL = $(LEAK)
%.check: %.test
	@echo -e "check completed"
	@echo -e "    logfile:   " $(BOLD) $(LOGFILE) $(RESET)
	@echo -e "    valgrind:  " $(BOLD) "$^.valgrind" $(RESET)

%.debug: MEMCHECK = gdb
%.debug: %.test
	@echo "exiting debugger"

test.o: test.h

result:
	@echo -e "\n$(TIMESTAMP) - tests done" >> $(LOGFILE)
	@echo -e "$(tests_run) tests run\nlogfile: $(LOGFILE)\n"

clean:
	rm -f *.test *.o
	@rm -f $(LOGFILE)

realclean: clean
	rm -f lsdb-test-????????.log* ????-????.test.valgrind
	rm -rf ????-????.tmp.*

