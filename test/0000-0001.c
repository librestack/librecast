#include "test.h"
#include <librecast/net.h>

int main()
{
	lc_ctx_t *lctx;
	lc_socket_t *sock, *sock2;

	test_name("lc_socket_new() / lc_socket_close()");

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);

	lc_socket_close(sock);
	lc_ctx_free(lctx);

	/* lc_ctx_free() should clean up socket without needing explicit lc_socket_close() */
	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	sock2 = lc_socket_new(lctx);
	test_assert(sock2 != NULL, "sock2");
	lc_ctx_free(lctx);

	if (RUNNING_ON_VALGRIND) return fails;

	/* force ENOMEM */
	falloc_setfail(1);
	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	test_assert(errno == ENOMEM, "lc_socket_new() - ENOMEM");
	test_assert(sock == NULL, "lc_socket_new() - ENOMEM, return NULL");
	lc_ctx_free(lctx);

	return fails;
}
