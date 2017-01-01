#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
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
	char buf[LINE_MAX];
	if (errsv != 0) {
		strerror_r(errsv, buf, sizeof(buf));
		logmsg(LOG_SEVERE, "%s: %s", errstr, buf);
	}
	else if (e != 0) {
		logmsg(LOG_SEVERE, "%s: %s", errstr, error_msg(e));
	}
}
