#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "main.h"
#include "config.h"
#include "errors.h"
#include "log.h"
#include "signals.h"

char *getlockfilename()
{
	char *lockfile;

	if (geteuid() == 0) {
		/* we are root, put lockfile in /var/run */
		asprintf(&lockfile, "/var/run/%s.pid", PROGRAM_NAME);
	}
        else {
		/* not root, put pidfile in user home */
	        asprintf(&lockfile, "%s/.%s.pid", getenv("HOME"), PROGRAM_NAME);
	}


	return lockfile;
}

int obtain_lockfile()
{
        char *lockfile;
	int fd;

        lockfile = getlockfilename();
        fd = open(lockfile, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP
		| S_IWGRP | S_IROTH );
	free(lockfile);

	return fd;
}

int main()
{
	int e, errsv;
	int lockfd;
	int signal = 0;
	char buf[sizeof(char) + sizeof(long) + 1];

	e = sighandlers();
	if (e != 0) {
		goto main_fail;
	}

	/* process arguments and options */

	/* read config */

	/* obtain lockfile, but don't write pid until after we fork() */
	lockfd = obtain_lockfile();
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

	/* daemonise */

	/* write pid to lockfile */
	snprintf(buf, sizeof(long), "#%ld\n", (long) getpid());
	if (write(lockfd, buf, strlen(buf)) != strlen(buf)) {
		errno = 0;
		e = ERROR_PID_WRITEFAIL;
		goto main_fail;
	}
	e = signal_daemon(SIGTERM, lockfd);
	if (e != 0) {
		errno = 0;
		goto main_fail;
	}

	free_config();

	return 0;

main_fail:
	errsv = errno;
	print_error(e, errsv, "main");
	free_config();
	return e;
}
