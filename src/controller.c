#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "config.h"
#include "controller.h"
#include "errors.h"

void controller_start(int lockfd)
{
	int e, errsv;
	char buf[sizeof(char) + sizeof(long) + 1];

	/* daemonize */
	if (config_get_num("daemon") == 1) {
		if (daemon(0, 0) != 0) {
			e = ERROR_DAEMON_FAILURE;
			goto controller_start_fail;
		}
	}

	/* write pid to lockfile */
	snprintf(buf, sizeof(long), "#%ld\n", (long) getpid());
	if (write(lockfd, buf, strlen(buf)) != strlen(buf)) {
		errno = 0;
		e = ERROR_PID_WRITEFAIL;
		goto controller_start_fail;
	}

	/* dump config to pidfile */
	config_print(lockfd);


	for (;;) {
		/* do stuff here */
	}

	config_free();

	return;

controller_start_fail:
	errsv = errno;
	print_error(e, errsv, "controller_start");
	config_free();
	_exit(e);
}
