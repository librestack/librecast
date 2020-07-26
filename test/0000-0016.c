#include "test.h"
#include "../src/errors.h"
#include "../src/log.h"
#include <stdlib.h>

int main()
{
	char dbpath[] = "0000-0016.tmp.XXXXXX";
	test_name("lc_db_set() / lc_db_get()");
	LOG_LEVEL = 127;
	lc_ctx_t *lctx = lc_ctx_new();

	test_assert(lc_db_open(lctx, mkdtemp(dbpath)) == 0, "lc_db_open() - open temp db");
	char db[] = "black";
	char key[] = "lives";
	char val[] = "matter";
	test_assert(lc_db_set(lctx, db, key, strlen(key), val, strlen(val)) == 0,
				"lc_db_set()");

	void *vptr = NULL;
	size_t vlen;
	test_assert(lc_db_get(lctx, db, (void *)key, strlen(key), &vptr, &vlen) == 0,
				"lc_db_get()");

	test_expectn(val, (char *)vptr, vlen); /* check we read back wot we wrote */

	free(vptr);

	lc_ctx_free(lctx);
	return fails;
}
