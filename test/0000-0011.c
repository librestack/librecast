#include "test.h"
#include "../src/errors.h"
#include "../src/log.h"

int main()
{
	result("lc_socket_listen() / lc_socket_listen_cancel()");
	LOG_LEVEL = 0;
	lc_ctx_t *lctx = NULL;
	lc_socket_t *sock = NULL; 
	lc_channel_t *chan = NULL;

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	chan = lc_channel_new(lctx, "example.com");

	lc_channel_bind(sock, chan);
	lc_channel_join(chan);

	test_assert(lc_socket_listen(NULL, NULL, NULL) == LC_ERROR_SOCKET_REQUIRED,
			"lc_socket_listen requires socket");

	test_assert(lc_socket_listen(sock, NULL, NULL) == 0,
			"lc_socket_listen() returns 0 on success");

	test_assert(lc_socket_listen_cancel(sock) == 0,
			"lc_socket_listen_cancel() returns 0 on success");

	test_assert(lc_socket_listen_cancel(sock) == 0,
			"lc_socket_listen_cancel() can be called twice");

	test_assert(lc_socket_listen(sock, NULL, NULL) == 0,
			"lc_socket_listen() returns 0 on success");

	test_assert(lc_socket_listen(sock, NULL, NULL) == LC_ERROR_SOCKET_LISTENING,
			"lc_socket_listen() returns LC_ERROR_SOCKET_LISTENING when socket busy");

	test_assert(lc_socket_listen_cancel(sock) == 0,
			"lc_socket_listen_cancel() returns 0 on success");

	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);

	return fails;
}
