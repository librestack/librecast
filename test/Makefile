# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2017-2021 Brett Sheffield <bacs@librecast.net>

SHELL := /bin/bash
CFLAGS += -O2 -Wall -Wextra -Wpedantic -fno-builtin-malloc -fno-builtin-calloc -g -I. -I../include
ifdef USE_LIBSODIUM
CFLAGS += -DUSE_LIBSODIUM=$(USE_LIBSODIUM)
else
CFLAGS += -I../libs/blake3/c
endif
NOTOBJS := ../src/$(PROGRAM).o
OBJS := test.o misc.o falloc.o
LIBRARY_PATH := ../src
LDFLAGS := -L$(LIBRARY_PATH) -ldl -llibrecast
BOLD := "\\e[0m\\e[2m"
RESET := "\\e[0m"
PASS = "\\e[0m\\e[32mOK\\e[0m" # end bold, green text
FAIL = "\\e[0m\\e[31mFAIL\\e[0m" # end bold, red text
LEAK = "\\e[0m\\e[31mFAIL \| LEAK\\e[0m\\n\\tSee $@.valgrind"
LASTLOG := lastlog.log
LOGFILE := $(shell mktemp "lsdb-test-XXXXXXXX.log")
TIMESTAMP = $(shell date +"%Y-%m-%d %H:%M:%S")
VALGRIND = valgrind --leak-check=full --error-exitcode=2 --errors-for-leak-kinds=all --track-origins=yes --log-file=$@.valgrind

.PHONY: test clean realclean build result check

check: MEMCHECK = $(VALGRIND)
check: FAIL = $(LEAK)
check: test

test: clean build $(shell echo ????-????.c | sed 's/\.c/\.test/g') result

build:
	cd ../src && $(MAKE)
	ldconfig -n $(LIBRARY_PATH)
	@echo -e "$(TIMESTAMP) - starting tests" >> $(LOGFILE)
	@echo -e "\nRunning tests"

0000-0019.test: LDFLAGS += -pthread

%.test: %.c clean build $(OBJS)
	@$(CC) $(CFLAGS) -o $@ $< $(OBJS) $(LDFLAGS)
	@echo -ne "\e[2m" $* " "
	@echo -ne "\n== $@" >> $(LOGFILE)
	@LD_LIBRARY_PATH=$(LIBRARY_PATH) $(MEMCHECK) ./$@ 2>> $(LOGFILE) && echo -e " $(PASS)" || echo -e " $(FAIL)"
	@ln -sf $(LOGFILE) $(LASTLOG)
	@$(eval tests_run=$(shell echo $$(($(tests_run)+1))))

%.check: MEMCHECK = $(VALGRIND)
%.check: FAIL = $(LEAK)
%.check: %.test
	@echo "check completed"
	@echo -e "    logfile:   " $(BOLD) $(LOGFILE) / $(LASTLOG) $(RESET)
	@echo -e "    valgrind:  " $(BOLD) "$^.valgrind" $(RESET)

%.debug: MEMCHECK = gdb
%.debug: %.test
	@echo "exiting debugger"

falloc.o: falloc.h

test.o: test.h

result:
	@echo -e "\n$(TIMESTAMP) - tests done" >> $(LOGFILE)
	@echo -e "$(tests_run) tests run\nlogfile: $(LOGFILE)\n"

clean:
	rm -f *.test *.o
	@rm -f $(LOGFILE) $(LASTLOG)

realclean: clean
	rm -f lsdb-test-????????.log* ????-????.test.valgrind
	rm -rf ????-????.tmp.*

