#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "config.h"
#include "controller.h"
#include "errors.h"
#include "log.h"
#include "net.h"

void controller_start(int lockfd)
{
	int e, errsv;
	char buf[sizeof(char) + sizeof(long) + 1];

	logmsg(LOG_INFO, "starting controller");

	/* daemonize */
	if (config_get_num("daemon") == 1) {
		logmsg(LOG_INFO, "forking controller process");
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

	net_multicast_init();
	net_multicast_listen();

	for (;;) {
		/* do stuff here */
		char *msg = config_get("pingtext");
		net_multicast_send(msg);
		sleep(2);
	}

	/* never reached */
	config_free();

	return;

controller_start_fail:
	errsv = errno;
	print_error(e, errsv, "controller_start");
	config_free();
	_exit(e);
}
