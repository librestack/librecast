.PHONY: test clean result

test: clean $(shell echo *.c | sed 's/\.c/\.test/g') result

%.test: %.c
	@$(CC) -o $@ $^
	@echo -n $*
	@./$@ && echo " PASS" || echo " FAIL"
	@$(eval tests_run=$(shell echo $$(($(tests_run)+1))))

result:
	@echo $(tests_run) tests run

clean:
	rm -f *.test
