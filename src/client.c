#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include "main.h"
#include "config.h"
#include "errors.h"
#include "args.h"
#include "log.h"
#include "pid.h"
#include "signals.h"

int main(int argc, char **argv)
{
	int e, errsv;
	int lockfd;

	config_set_num("loglevel", LOG_DEBUG);

	if ((e = args_process(argc, argv)) != 0) {
		goto main_fail;
	}

	lockfd = obtain_lockfile(O_RDONLY);
	if (lockfd == -1) {
		errno = 0;
		e = ERROR_PID_OPEN;
		goto main_fail;
	}

	if (argc != 2) {
		e = ERROR_INVALID_ARGS;
		goto main_fail;
	}

	if (!args_valid_arg(argv[1])) {
		e = ERROR_INVALID_ARGS;
		goto main_fail;
	}

	if (strcmp(argv[1], "stop") == 0)
		signal_daemon(SIGINT, lockfd);

main_fail:
	errsv = errno;
	print_error(e, errsv, "main");
	return 0;
}
