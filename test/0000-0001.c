#include "test.h"

int main()
{
	result("lc_socket_new() / lc_socket_close()");

	lc_ctx_t *lctx;
	lc_socket_t *sock;

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);

	lc_socket_close(sock);
	lc_ctx_free(lctx);

	return 0;
}
