#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include "config.h"
#include "log.h"
#include "misc.h"

void logmsg(int level, char *msg, ...)
{
	va_list argp;
	char *b;
	int loglevel;

	loglevel = (int) config_get_num("loglevel");
	if (loglevel < level)
		return;

	va_start(argp, msg);
	b = malloc(_vscprintf(msg, argp));
	vsprintf(b, msg, argp);
	va_end(argp);
	fprintf(stderr, "%s\n", b);
	free(b);
}
