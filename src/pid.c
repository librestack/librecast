#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "main.h"

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

int obtain_lockfile(int flags)
{
        char *lockfile;
	int fd;

        lockfile = getlockfilename();
        fd = open(lockfile, flags, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP |
			S_IROTH);
	free(lockfile);

	return fd;
}
