#include <stdio.h>
#include <librecast.h>

int main()
{
	return (librecast_running() == 1) ? 0 : 1;
}
