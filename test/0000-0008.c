#include "test.h"
#include <librecast/net.h>

int main()
{
	test_name("lc_ctx_get_id()");
	lc_ctx_t *lctx = NULL;
	uint32_t id;

	id = lc_ctx_get_id(lctx);
	test_assert(id == 0, "expected 0 when calling lc_channel_get_id(NULL)");

	lctx = lc_ctx_new();
	id = lc_ctx_get_id(lctx);
	test_assert(id != 0, "expected ctx id when calling lc_ctx_get_id()");

	lc_ctx_free(lctx);

	return fails;
}
