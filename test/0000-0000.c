#include "test.h"

int main()
{
	result("lc_ctx_new() / lc_ctx_free()");

	lc_ctx_t * lctx;
	lctx = lc_ctx_new();
	lc_ctx_free(lctx);

	return fails;
}
