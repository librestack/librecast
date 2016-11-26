#include "commands.h"
#include "config.h"
#include "controller.h"
#include "errors.h"
#include "main.h"
#include "log.h"

char *command_cmd(int code)
{
	switch (code) {
		COMMAND_CODES(COMMAND_CMD)
	}
	return '\0';
}

/*****************************************************************************/
/* remote commands                                                           */

int command_noop()
{
	return 0;
}

int command_reload()
{
	config_reload();
	controller_reload();
	return 0;
}

int command_stop()
{
	main_free();
	return 0;
}

int command_ping()
{
	logmsg(LOG_DEBUG, "PING");
	return 0;
}

int command_time()
{
	return 0;
}

/*****************************************************************************/
