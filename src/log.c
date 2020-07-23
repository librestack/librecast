#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include "log.h"
#include "misc.h"

void logmsg(int level, char *msg, ...)
{
	va_list argp;
	char *b;
	int loglevel;

	loglevel = 127;
	if ((loglevel & level) != level)
		return;

	va_start(argp, msg);
	b = malloc(_vscprintf(msg, argp) + 1);
	assert(b != NULL);
	vsprintf(b, msg, argp);
	va_end(argp);
	fprintf(stderr, "%s\n", b);
	free(b);
}
