#include <stdio.h>
#include <librecast.h>

int main()
{
	return (librecast_running() == 0) ? 0 : 1;
}
