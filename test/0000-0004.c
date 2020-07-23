#include "test.h"

int main()
{
	result("lc_msg_init_size() / lc_msg_free()");

	lc_message_t msg;
	lc_msg_init_size(&msg, 1024);
	lc_msg_free(&msg);

	return 0;
}
