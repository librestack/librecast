#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include "log.h"
#include "misc.h"

unsigned int LOG_LEVEL = LOG_WARNING;

void logmsg(int level, char *msg, ...)
{
	va_list argp;
	char *b;

	if (LOG_LEVEL < level)
		return;

	va_start(argp, msg);
	b = malloc(_vscprintf(msg, argp));
	vsprintf(b, msg, argp);
	va_end(argp);
	fprintf(stderr, "%s", b);
	free(b);
}
