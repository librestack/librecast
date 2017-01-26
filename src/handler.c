#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "commands.h"
#include "errors.h"
#include "log.h"
#include "net.h"
#include "socket.h"

int handler_handle_request(char *req, char *src)
{
	int e = 0;
	net_header_t h;

	if (socket_connect() == 0) {
		logmsg(LOG_DEBUG, "got src: '%s'", src);
		socket_send(src, strlen(src));
		socket_close();
	}
	net_unpack(&h, req);
	logmsg(LOG_DEBUG, "received: %i: %li %i", h.seq, (long)h.timestamp, h.cmd);
	logmsg(LOG_DEBUG, "%s", command_cmd(h.cmd));

	switch(h.cmd) {
		COMMAND_CODES(COMMAND_FUNC)
		default:
			logmsg(LOG_ERROR, "Undefined command");
	}

	return e;
}
