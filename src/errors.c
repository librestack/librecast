#include <errno.h>
#include <stdio.h>
#include "log.h"
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
		logmsg(LOG_SEVERE, "%s: %s\n", errstr, error_msg(e));
}
