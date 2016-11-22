#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "errors.h"
#include "signals.h"

int sighandlers()
{
	signal(SIGHUP, sighup_handler);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigterm_handler);

	return ERROR_SUCCESS;
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
