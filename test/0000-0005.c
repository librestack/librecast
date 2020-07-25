#include "test.h"

int main()
{
	test_name("lc_msg_init_data()");

	lc_message_t msg;
	lc_msg_init_data(&msg, "some data", 10, NULL, NULL);

	return fails;
}
