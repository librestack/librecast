#include "test.h"

int main()
{
	test_name("lc_socket_new() / lc_socket_close()");

	lc_ctx_t *lctx;
	lc_socket_t *sock;

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);

	lc_socket_close(sock);
	lc_ctx_free(lctx);

	return fails;
}
