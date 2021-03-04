#include "test.h"
#include <librecast/net.h>

int main()
{
	lc_ctx_t *lctx = NULL;
	lc_socket_t *sock = NULL; 
	lc_channel_t *chan = NULL;

	test_name("lc_channel_join() / lc_channel_part()");

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	chan = lc_channel_new(lctx, "example.com");

	lc_channel_bind(sock, chan);

	test_assert(lc_channel_join(chan) == 0,
			"lc_channel_join() returns 0 on success");

	/* TODO: test failure (remove all interfaces) */

	test_assert(lc_channel_part(chan) == 0,
			"lc_channel_part() returns 0 on success");

	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);

	return fails;
}
