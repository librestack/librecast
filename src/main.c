#include <errno.h>
#include <stdio.h>
#include "main.h"
#include "errors.h"
#include "log.h"
#include "signals.h"

int main()
{
	int e, errsv;

	e = sighandlers();
	if (e != 0) {
		goto main_fail;
	}

	return 0;
main_fail:
	errsv = errno;
	print_error(e, errsv, "main");
	return 1;
}
