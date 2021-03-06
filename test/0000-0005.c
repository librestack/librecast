#include "test.h"
#include <librecast/net.h>

static int freed;

static void *dataptr, *hintptr;

void *freeme(void *data, void *hint)
{
	test_log("%p == %p\n", data, dataptr);
	test_assert(data == dataptr, "msg free called with msg ptr (%zd)",
			(char *)data-(char *)dataptr );
	test_assert(hint == hintptr, "msg free called with hint (%zd)",
			(char *)hint-(char *)hintptr );
	freed++;
	return NULL;
}

int main()
{
	lc_message_t msg;
	char data[] = "some data";
	size_t len = strlen(data) + 1;

	test_name("lc_msg_init_data()");

	lc_msg_init_data(&msg, data, len, &freeme, &msg);
	test_assert(msg.data == data, "msg.data points to our buffer");
	test_assert(msg.len == len, "msg.len set");
	dataptr = msg.data;
	hintptr = &msg;
	lc_msg_free(&msg);

	test_assert(freed == 1, "message free function called");

	return fails;
}
