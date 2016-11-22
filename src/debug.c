#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include "debug.h"
#include "misc.h"

void debug_print(char *msg, ...)
{
	va_list argp;
	char *b;

	va_start(argp, msg);
	b = malloc(_vscprintf(msg, argp));
	vsprintf(b, msg, argp);
	va_end(argp);
	fprintf(stderr, "%s", b);
	free(b);
}
