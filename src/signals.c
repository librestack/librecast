#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "errors.h"
#include "signals.h"

int sighandlers()
{
	signal(SIGHUP, sighup_handler);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigterm_handler);

	return 0;
}

void sighup_handler (int signo)
{
	// do nothing, yet
}

void sigint_handler (int signo)
{
	sigterm_handler(signo);
}

void sigterm_handler (int signo)
{
	_exit(EXIT_SUCCESS);
}

int signal_daemon (int signal, int lockfd)
{
        char buf[sizeof(long)] = "";
        long pid;

        if (pread(lockfd, &buf, sizeof(buf), 1) == -1) {
                return ERROR_PID_READFAIL;
        }
        if (sscanf(buf, "%li", &pid) == 1) {
                return kill(pid, signal);
        }
        else {
                return ERROR_PID_INVALID;
        }
}
