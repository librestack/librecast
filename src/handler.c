#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int handler_handle_request(char *req)
{
	time_t timer;

	time(&timer);
	printf("%.*s : %s\n", (int)strlen(ctime(&timer)) - 1, ctime(&timer), req);

	return 0;
}
