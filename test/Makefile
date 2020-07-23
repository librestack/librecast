LIBS = -llibrecast
PASS = "\\e[0m\\e[32m" # end bold, green text
FAIL = "\\e[0m\\e[31m" # end bold, red text


.PHONY: test clean result memcheck

memcheck: MEMCHECK = valgrind -q --leak-check=full --error-exitcode=2 --errors-for-leak-kinds=all

memcheck: test

test: clean $(shell echo ????-????.c | sed 's/\.c/\.test/g') result

%.test: %.c test.o
	@$(CC) -o $@ $^ $(LIBS)
	@echo -ne "\e[2m" $* " "
	@$(MEMCHECK) ./$@ 2> /dev/null && echo -e " $(PASS)OK\e[0m" || echo -e " $(FAIL)FAIL\e[0m"
	@$(eval tests_run=$(shell echo $$(($(tests_run)+1))))

test.o: test.h

result:
	@echo $(tests_run) tests run

clean:
	rm -f *.test *.o
