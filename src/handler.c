#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "commands.h"
#include "errors.h"
#include "log.h"

int handler_handle_request(char *req)
{
	int e;
	long code;
	char *nptr;
	char *cmd;

	code = strtol(req, &nptr, 10);
	if (nptr != '\0') {
		e = ERROR_CMD_INVALID;
		print_error(e, 0, req);
	}
	else {
		cmd = command_cmd(code);
		logmsg(LOG_DEBUG, "%s", cmd);
	}

	return e;
}
