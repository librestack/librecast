#include <errno.h>
#include <stdio.h>
#include "debug.h"
#include "errors.h"

char *error_msg(int e)
{
	switch (e) {
		ERROR_CODES(ERROR_MSG)
	}
	return "Unknown error";
}

void print_error(int e, int errsv, char *errstr)
{
	if (errsv != 0)
		perror(errstr);
	else
		debug_print("%s: %s\n", errstr, error_msg(e));
}
