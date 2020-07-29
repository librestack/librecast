#include "test.h"
#include <librecast/net.h>

int main()
{
	test_name("lc_msg_init_size() / lc_msg_free()");

	lc_message_t msg;
	test_assert(!lc_msg_init_size(&msg, 1024), "lc_msg_init_size()");
	lc_msg_free(&msg);

	return fails;
}
