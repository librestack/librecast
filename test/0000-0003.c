#include "test.h"
#include <librecast/net.h>

int main()
{
	test_name("lc_msg_init()");

	lc_message_t msg;
	lc_msg_init(&msg);

	return fails;
}
