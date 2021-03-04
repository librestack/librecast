#include "test.h"
#include <librecast/net.h>

int main()
{
	lc_ctx_t *lctx;
	lc_channel_t *chan;

	test_name("lc_channel_new() / lc_channel_free()");

	lctx = lc_ctx_new();
	chan = lc_channel_new(lctx, "example.com");
	test_assert(chan != NULL, "lc_channel_new() - channel allocated (1)");

	lc_channel_free(chan);
	lc_ctx_free(lctx);

	/* lc_ctx_free() should clean up channel without needing explicit lc_channel_free() */
	lctx = lc_ctx_new();
	chan = lc_channel_new(lctx, "clean exit");
	test_assert(chan != NULL, "lc_channel_new() - channel allocated (2)");
	lc_ctx_free(lctx);

	if (RUNNING_ON_VALGRIND) return fails;

	/* force ENOMEM */
	lctx = lc_ctx_new();
	falloc_setfail(0);
	chan = lc_channel_init(lctx, NULL);
	test_assert(errno == ENOMEM, "lc_channel_new() - ENOMEM");
	test_assert(chan == NULL, "lc_channel_new() - ENOMEM, return NULL");
	chan = lc_channel_nnew(lctx, NULL, 0);
	test_assert(errno == ENOMEM, "lc_channel_new() - ENOMEM");
	test_assert(chan == NULL, "lc_channel_new() - ENOMEM, return NULL");
	lc_ctx_free(lctx);

	return fails;
}
