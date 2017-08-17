#include <stdio.h>
#include <string.h>
#include "args.h"
#include "config.h"
#include "errors.h"
#include "log.h"

int args_process(int argc, char **argv)
{
	int i, e;

	if (argc == 0)
		return 0;

	logmsg(LOG_DEBUG, "program called as %s", argv[0]);

	for (i=1; i < argc; i++) {
		if ((e = args_process_arg(argv[i])) != 0)
			return e;
	}

	return 0;
}

int args_process_arg(char *arg)
{
	logmsg(LOG_TRACE, "args_process_arg(%s)", arg);

	if (!args_valid_arg(arg)) {
		logmsg(LOG_ERROR, "'%s' is not a valid argument", arg);
		return LC_ERROR_INVALID_ARGS;
	}

	return 0;
}

int args_signal(char *arg)
{
	ARGS_ARGS(ARGS_SIGNAL)
	return 0;
}

int args_valid_arg(char *arg)
{
	ARGS_ARGS(ARGS_ARG)
	return 0;
}
