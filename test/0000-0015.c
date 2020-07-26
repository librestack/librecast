#include "test.h"
#include "../src/errors.h"
#include "../src/log.h"

int main()
{
	test_name("lc_db_open()");
	LOG_LEVEL = 127;
	lc_ctx_t *lctx = lc_ctx_new();
	test_assert(lc_db_open(lctx, NULL) == 0, "lc_db_open()");
	lc_ctx_free(lctx);
	return fails;
}
