#include "test.h"
#include <librecast/net.h>

int main()
{
	lc_ctx_t * lctx;

	test_name("lc_ctx_new() / lc_ctx_free()");

	lctx = lc_ctx_new();
	lc_ctx_free(lctx);

	if (RUNNING_ON_VALGRIND) return fails;

	/* force ENOMEM */
	falloc_setfail(0);
	lctx = lc_ctx_new();
	test_assert(errno == ENOMEM, "lc_ctx_new() - ENOMEM");
	test_assert(lctx == NULL, "lc_ctx_new() - ENOMEM, return NULL");

	return fails;
}
