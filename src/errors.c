#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include "log.h"
#include "errors.h"

int lc_error_log(int level, int e)
{
	logmsg(level, "%s", lc_error_msg(e));
	return e;
}

char *lc_error_msg(int e)
{
	switch (e) {
		LC_ERROR_CODES(LC_ERROR_MSG)
	}
	return "Unknown error";
}

void lc_print_error(int e, int errsv, char *errstr)
{
	char buf[LINE_MAX];
	if (errsv != 0) {
		strerror_r(errsv, buf, sizeof(buf));
		logmsg(LOG_SEVERE, "%s: %s", errstr, buf);
	}
	else if (e != 0) {
		logmsg(LOG_SEVERE, "%s: %s", errstr, lc_error_msg(e));
	}
}
