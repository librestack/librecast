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

#define MAX_UNIX_CLIENTS 8

int s_local;
char *sockname;

/* initialize local socket */
static int socket_init();

void socket_close()
{
	close(s_local);
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
	if (bind(s_local, (struct sockaddr *)&addr, len) != 0) {
		errsv = errno;
		lc_print_error(e, errsv, "socket_bind");
		e = LC_ERROR_SOCKET_CONNECT;
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
	if (connect(s_local, (struct sockaddr *)&addr, len) != 0) {
		errsv = errno;
		lc_print_error(e, errsv, "socket_connect");
		e = LC_ERROR_SOCKET_CONNECT;
	}
	free(sockname);

	return e;
}

static int socket_init(struct sockaddr_un *addr, size_t *len)
{
	int e = 0, errsv;

	errno = 0;

	logmsg(LOG_DEBUG, "creating unix socket");
	if ((s_local = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
		errsv = errno;
		lc_print_error(e, errsv, "socket_init");
		return LC_ERROR_SOCKET_CREATE;
	}

	addr->sun_family = AF_UNIX;
	sockname = getsockfilename();
	strcpy(addr->sun_path, sockname);
	*len = sizeof(addr->sun_path) + sizeof(addr->sun_family);

	return 0;
}

int socket_read(char *buf)
{
	int bytes, errsv;

	bytes = recv(s_local, buf, 1024, MSG_DONTWAIT);
	if (bytes == -1) {
		errsv = errno;
		lc_print_error(0, errsv, "socket_read");
	}

	return bytes;
}

int socket_send(char *buf, size_t len)
{
	int bytes, errsv;

	bytes = send(s_local, buf, len, 0);
	if (bytes == -1) {
		errsv = errno;
		lc_print_error(0, errsv, "socket_send");
	}

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
