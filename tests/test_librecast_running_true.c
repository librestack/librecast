#include <stdio.h>
#include "../include/librecast.h"

int main()
{
	return (lc_librecast_running() == LIBRECASTD_RUNNING) ? 0 : 1;
}
