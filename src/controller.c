#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "commands.h"
#include "config.h"
#include "controller.h"
#include "errors.h"
#include "log.h"
#include "net.h"

pthread_t tid[2];

void controller_join_all()
{
	CONTROLLER_THREADS(CONTROLLER_THREADS_JOIN)
}

void * controller_ping()
{
	char msg[16];
	net_header_t h;

	h.cmd = CMD_PING;
	for (;;) {
		net_pack(h, msg);
		logmsg(LOG_DEBUG, "sending %i: %li %i\n", h.seq, h.timestamp, h.cmd);
		net_multicast_send(msg, 16);
		sleep(1);
	}
}

void controller_reload()
{
	net_multicast_setoptions();
}

void controller_thread_join(int id, char *desc)
{
	pthread_join(tid[id], NULL);
	logmsg(LOG_DEBUG, "%s thread stopped", desc);
}

void controller_shutdown()
{
	CONTROLLER_THREADS(CONTROLLER_THREADS_CANCEL)
	CONTROLLER_THREADS(CONTROLLER_THREADS_JOIN_EX)
}

void controller_start(int lockfd)
{
	int e, errsv;

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
	if (!dprintf(lockfd, "#%ld\n", (long) getpid())) {
		errno = 0;
		e = ERROR_PID_WRITEFAIL;
		goto controller_start_fail;
	}

	/* dump config to pidfile */
	config_print(lockfd);

	net_multicast_init();

	/* start controller threads */
	pthread_attr_t attr = {};
	CONTROLLER_THREADS(CONTROLLER_THREADS_START)
	CONTROLLER_THREADS(CONTROLLER_THREADS_JOIN)

	/* never reached (unless we ever make all threads exit without being cancelled */
	return;

controller_start_fail:
	errsv = errno;
	print_error(e, errsv, "controller_start");
	config_free();
	_exit(e);
}

void * controller_f(int thread)
{
	switch (thread) {
		CONTROLLER_THREADS(CONTROLLER_THREADS_F)
		default:
			return NULL;
	}
}
