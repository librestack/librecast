#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

char *getlockfilename(char *program)
{
	char *lockfile;

	if (geteuid() == 0) {
		/* we are root, put lockfile in /var/run */
		asprintf(&lockfile, "/var/run/%s.pid", program);
	}
        else {
		/* not root, put pidfile in user home */
	        asprintf(&lockfile, "%s/.%s.pid", getenv("HOME"), program);
	}


	return lockfile;
}

int obtain_lockfile(char *program)
{
        char *lockfile;
	int fd;

        lockfile = getlockfilename(program);
        fd = open(lockfile, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR |
		        S_IRGRP | S_IWGRP | S_IROTH );
	free(lockfile);

	return fd;
}
