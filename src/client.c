#include <sys/stat.h>
#include <fcntl.h>
#include "main.h"
#include "errors.h"
#include "log.h"
#include "pid.h"
#include "signals.h"

int main(int argc, char **argv)
{
	int e, errsv;
	int lockfd;

	lockfd = obtain_lockfile(O_RDONLY);
	if (lockfd == -1) {
		errno = 0;
		e = ERROR_PID_OPEN;
		goto main_fail;
	}

main_fail:
	errsv = errno;
	print_error(e, errsv, "main");
	return 0;
}
