#include "test.h"

int main()
{
	result("lc_msg_init()");

	lc_message_t msg;
	lc_msg_init(&msg);

	return 0;
}
