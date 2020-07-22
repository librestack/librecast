LIBS = -llibrecast
MEMCHECK = valgrind -q --leak-check=full --error-exitcode=2 --errors-for-leak-kinds=all

.PHONY: test clean result

test: clean $(shell echo *.c | sed 's/\.c/\.test/g') result

%.test: %.c test.h
	@$(CC) -o $@ $^ $(LIBS)
	@echo -n $* " "
	@$(MEMCHECK) ./$@ 2> /dev/null && echo " PASS" || echo " FAIL"
	@$(eval tests_run=$(shell echo $$(($(tests_run)+1))))

result:
	@echo $(tests_run) tests run

clean:
	rm -f *.test
