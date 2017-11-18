#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include "main.h"
#include "client.h"
#include "config.h"
#include "errors.h"
#include "args.h"
#include "log.h"
#include "pid.h"
#include "socket.h"

int signal_daemon (int signal, int lockfd)
{
	char buf[sizeof(long)] = "";
	long pid;

	if (pread(lockfd, &buf, sizeof(buf), 1) == -1) {
		return LC_ERROR_PID_READFAIL;
	}
	if (sscanf(buf, "%li", &pid) == 1) {
		return kill(pid, signal);
	}
	else {
		return LC_ERROR_PID_INVALID;
	}
}

int main(int argc, char **argv)
{
	int e, errsv;
	int lockfd;
	int signal;

	config_set_num("loglevel", 15);

	if ((e = args_process(argc, argv)) != 0) {
		goto main_fail;
	}

	if ((lockfd = obtain_lockfile(O_RDONLY)) == -1) {
		errno = 0;
		e = LC_ERROR_PID_OPEN;
		goto main_fail;
	}

	if (argc != 2) {
		e = LC_ERROR_INVALID_ARGS;
		goto main_fail;
	}

	if (!args_valid_arg(argv[1])) {
		e = LC_ERROR_INVALID_ARGS;
		goto main_fail;
	}

	signal = args_signal(argv[1]);
	if (signal) {
		/* signal daemon */
		if (signal_daemon(signal, lockfd) != 0) {
			errsv = errno;
			if (errsv == ESRCH) {
				e = LC_ERROR_DAEMON_STOPPED;
				logmsg(LOG_ERROR, lc_error_msg(e));
				config_free();
				return e;
			}
			goto main_fail;
		}
	}
	else {
		/* connect to local socket for more complex communication */
		if ((e = socket_connect()) != 0) {
			errno = 0;
			goto main_fail;
		}

		/* TODO - send command & check response */

		socket_close();
	}

main_fail:
	errsv = errno;
	lc_print_error(e, errsv, "main");
	config_free();
	return 0;
}

void main_free()
{
	config_free();
}
