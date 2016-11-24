#define _GNU_SOURCE

#include <errno.h>
#include <sys/file.h>
#include <unistd.h>
#include "config.h"
#include "main.h"
#include "controller.h"
#include "errors.h"
#include "log.h"
#include "pid.h"
#include "signals.h"

int main(int argc, char **argv)
{
	int e, errsv;
	int lockfd;
	int signal = 0;

	e = sighandlers();
	if (e != 0) {
		goto main_fail;
	}

	/* set config defaults, before overriding them with any options */
	config_defaults();

	/* read config */
	if ((e = config_read(NULL)))
		goto main_fail;

	/* obtain lockfile, but don't write pid until after we fork() */
	lockfd = obtain_lockfile(O_RDWR | O_CREAT | O_TRUNC);
	if (lockfd == -1) {
		errno = 0;
		e = ERROR_PID_OPEN;
		goto main_fail;
	}
	else if (flock(lockfd, LOCK_EX|LOCK_NB) != 0) {
		if (signal != 0) {
			e = signal_daemon(signal, lockfd);
			_exit(e);
		}
		e = ERROR_ALREADY_RUNNING;
		goto main_fail;
	}

	/* open syslogger */

	/* start controller process */
	controller_start(lockfd);

	return 0;

main_fail:
	errsv = errno;
	print_error(e, errsv, "main");
	config_free();
	return e;
}
