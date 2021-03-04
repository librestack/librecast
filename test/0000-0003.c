#include "test.h"
#include <librecast/net.h>

int main()
{
	lc_message_t msg;

	test_name("lc_msg_init()");

	lc_msg_init(&msg);

	return fails;
}
