#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "commands.h"
#include "errors.h"
#include "log.h"
#include "net.h"

int handler_handle_request(char *req)
{
	int e = 0;

	net_header_t h;

	net_unpack(&h, req);
	printf("received: %i: %li %i\n", h.seq, h.timestamp, h.cmd);
	logmsg(LOG_DEBUG, "%s", command_cmd(h.cmd));

	switch(h.cmd) {
		COMMAND_CODES(COMMAND_FUNC)
		default:
			logmsg(LOG_ERROR, "Undefined command");
	}

	return e;
}
