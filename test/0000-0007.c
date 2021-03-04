#include "test.h"
#include <librecast/net.h>

int main()
{
	lc_ctx_t *lctx;
	lc_channel_t *chan = NULL;
	uint32_t id;

	test_name("lc_channel_get_id()");

	id = lc_channel_get_id(chan);
	test_assert(id == 0, "expected 0 when calling lc_channel_get_id(NULL)");

	lctx = lc_ctx_new();
	chan = lc_channel_new(lctx, "example.com");

	id = lc_channel_get_id(chan);
	test_assert(id != 0, "expected non-zero channel id when calling lc_channel_get_id()");

	lc_channel_free(chan);
	lc_ctx_free(lctx);

	return fails;
}
