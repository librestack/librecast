#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "config.h"
#include "controller.h"
#include "errors.h"
#include "main.h"
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
	config_reload();
	controller_reload();
}

void sigint_handler (int signo)
{
	sigterm_handler(signo);
}

void sigterm_handler (int signo)
{
	main_free();
}
