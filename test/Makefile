LIBS = -llibrecast
MEMCHECK = valgrind -q --leak-check=full --error-exitcode=2 --errors-for-leak-kinds=all
PASS = "\\e[0m\\e[32m"
FAIL = "\\e[0m\\e[31m"


.PHONY: test clean result

test: clean $(shell echo ????-????.c | sed 's/\.c/\.test/g') result

%.test: %.c test.h
	@$(CC) -o $@ $^ $(LIBS)
	@echo -ne "\e[2m" $* " "
	@$(MEMCHECK) ./$@ 2> /dev/null && echo -e " $(PASS)OK\e[0m" || echo -e " $(FAIL)FAIL\e[0m"
#	@./$@ && echo -e " $(PASS)OK\e[0m" || echo -e " $(FAIL)FAIL\e[0m"
	@$(eval tests_run=$(shell echo $$(($(tests_run)+1))))

result:
	@echo $(tests_run) tests run

clean:
	rm -f *.test
