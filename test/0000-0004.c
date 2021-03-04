#include "test.h"
#include <librecast/net.h>

int main()
{
	lc_message_t msg;

	test_name("lc_msg_init_size() / lc_msg_free()");

	test_assert(!lc_msg_init_size(&msg, 1024), "lc_msg_init_size()");
	lc_msg_free(&msg);

	if (RUNNING_ON_VALGRIND) return fails;

	/* force ENOMEM */
	falloc_setfail(0);
	test_assert(lc_msg_init_size(&msg, 1024) == -1, "lc_msg_init_size() - return -1 on ENOMEM");
	test_assert(errno == ENOMEM, "lc_msg_init_size() - errno set to ENOMEM");

	return fails;
}
