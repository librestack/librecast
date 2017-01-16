#include <stdio.h>
#include "../src/librecast.h"

int main()
{
	return (librecast_running() == LIBRECASTD_RUNNING) ? 0 : 1;
}
