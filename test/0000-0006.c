#include "test.h"
#include <librecast/net.h>

int main()
{
	test_name("lc_socket_get_id()");
	lc_ctx_t *lctx;
	lc_socket_t *sock = NULL;
	uint32_t sockid;

	sockid = lc_socket_get_id(sock);
	test_assert(sockid == 0, "expected 0 when calling lc_socket_get_id(NULL)");

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);

	sockid = lc_socket_get_id(sock);
	test_assert(sockid != 0, "expected non-zero socket id when calling lc_socket_get_id()");

	lc_socket_close(sock);
	lc_ctx_free(lctx);

	return fails;
}
