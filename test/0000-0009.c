#include "test.h"
#include "../src/errors.h"

int main()
{
	result("lc_channel_bind()");
	lc_ctx_t *lctx = NULL;
	lc_socket_t *sock = NULL; 
	lc_channel_t *chan = NULL;

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	chan = lc_channel_new(lctx, "example.com");

	test_assert(lc_channel_bind(NULL, chan) == LC_ERROR_SOCKET_REQUIRED,
			"lc_channel_bind requires socket");

	test_assert(lc_channel_bind(sock, NULL) == LC_ERROR_CHANNEL_REQUIRED,
			"lc_channel_bind requires channel");

	test_assert(lc_channel_bind(sock, chan) == 0,
			"lc_channel_bind returns 0 on success");

	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);

	return fails;
}
