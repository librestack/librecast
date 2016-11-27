#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "errors.h"
#include "log.h"
#include "main.h"
#include "socket.h"

int sock;
char *sockname;

/* initialize local socket */
static int socket_init();

void socket_close()
{
	close(sock);
}

int socket_bind()
{
	int e = 0, errsv;
	struct sockaddr_un addr;
	size_t len;

	if ((e = socket_init(&addr, &len)) != 0)
		return e;

	logmsg(LOG_DEBUG, "binding to unix socket '%s'", sockname);
	unlink(sockname);
	if (bind(sock, (struct sockaddr *)&addr, len) != 0) {
		errsv = errno;
		print_error(e, errsv, "socket_bind");
		e = ERROR_SOCKET_CONNECT;
	}
	free(sockname);

	return e;
}

int socket_connect()
{
	int e = 0, errsv;
	struct sockaddr_un addr;
	size_t len;

	if ((e = socket_init(&addr, &len)) != 0)
		return e;

	logmsg(LOG_DEBUG, "connecting to unix socket '%s'", sockname);
	if (connect(sock, (struct sockaddr *)&addr, len) != 0) {
		errsv = errno;
		print_error(e, errsv, "socket_connect");
		e = ERROR_SOCKET_CONNECT;
	}
	free(sockname);

	return e;
}

static int socket_init(struct sockaddr_un *addr, size_t *len)
{
	int e = 0, errsv;

	errno = 0;

	logmsg(LOG_DEBUG, "creating unix socket");
	if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
		errsv = errno;
		print_error(e, errsv, "socket_init");
		return ERROR_SOCKET_CREATE;
	}

	addr->sun_family = AF_LOCAL;
	sockname = getsockfilename();
	strcpy(addr->sun_path, sockname);
	*len = sizeof(addr->sun_path) + sizeof(addr->sun_family);

	return 0;
}

char *getsockfilename()
{
	char *sockfile;
        if (geteuid() == 0) {
		/* we are root, put lockfile in /var/run */
		asprintf(&sockfile, "/var/run/%s.sock", PROGRAM_NAME);
	}
        else {
		/* not root, put pidfile in user home */
		asprintf(&sockfile, "%s/.%s.sock",
		getenv("HOME"), PROGRAM_NAME);
	}
        return sockfile;
}
