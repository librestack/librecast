#include "test.h"
#include "../src/errors.h"
#include "../src/log.h"

int main()
{
	test_name("lc_db_open()");
	LOG_LEVEL = 127;
	lc_ctx_t *lctx = lc_ctx_new();
	test_assert(lc_db_open(lctx, NULL) == LC_ERROR_DB_REQUIRED,
			"lc_db_open() - NULL database -> LC_ERROR_DB_REQUIRED");
	test_assert(lc_db_open(lctx, "/tmp/does/not/exist") == LC_ERROR_DB_OPEN,
			"LC_ERROR_DB_OPEN for invalid db path");
	lc_ctx_free(lctx);
	return fails;
}
