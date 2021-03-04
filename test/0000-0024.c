#include "test.h"
#include "../src/librecast_pvt.h"
#include <librecast/net.h>
#include <netdb.h>

int main()
{
	lc_ctx_t *lctx;
	lc_channel_t *orig, *copy;
	struct in6_addr *oaddr, *caddr;

	test_name("lc_channel_copy()");

	lctx = lc_ctx_new();
	test_assert(lctx != NULL, "lc_ctx_new()");

	orig = lc_channel_new(lctx, "freedom");
	test_assert(orig != NULL, "lc_channel_new() - create orig channel");

	copy = lc_channel_copy(lctx, orig);
	test_assert(copy != NULL, "lc_channel_copy() - copy channel");

	/* ensure copy is actually a copy, not just the original */
	test_assert(copy != orig, "orig=%p, copy=%p", orig, copy);

	test_assert(copy->ctx == lctx, "copy->ctx set");

	oaddr = &lc_channel_sockaddr(orig)->sin6_addr;
	caddr = &lc_channel_sockaddr(copy)->sin6_addr;
	test_assert(!memcmp(caddr, oaddr, sizeof(struct in6_addr)),
			"copy->address set");

	lc_ctx_free(lctx);
	return fails;
}
