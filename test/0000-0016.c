#include "test.h"
#include "../src/errors.h"
#include "../src/log.h"
#include <stdlib.h>

int main()
{
	char dbpath[] = "0000-0016.tmp.XXXXXX";
	char db[] = "black";
	char key[] = "lives";
	char val[] = "matter";
	void *vptr = NULL;
	size_t vlen;

	test_name("lc_db_set() / lc_db_get()");
	LOG_LEVEL = 127;
	lc_ctx_t *lctx = lc_ctx_new();

	/* do all the bad things with no database */
	test_assert(lc_db_set(NULL, NULL, NULL, 0, NULL, 0) == LC_ERROR_CTX_REQUIRED,
			"lc_db_set() NULL ctx => LC_ERROR_CTX_REQUIRED");
	test_assert(lc_db_set(lctx, NULL, NULL, 0, NULL, 0) == LC_ERROR_DB_REQUIRED,
			"lc_db_set() db not open => LC_ERROR_DB_REQUIRED");

	test_assert(lc_db_get(NULL, NULL, NULL, 0, NULL, &vlen) == LC_ERROR_CTX_REQUIRED,
			"lc_db_get() NULL ctx => LC_ERROR_CTX_REQUIRED");
	test_assert(lc_db_get(lctx, NULL, NULL, 0, NULL, &vlen) == LC_ERROR_DB_REQUIRED,
			"lc_db_get() db not open => LC_ERROR_DB_REQUIRED");

	/* now actually open the database */
	test_assert(lc_db_open(lctx, mkdtemp(dbpath)) == 0, "lc_db_open() - open temp db");

	/* do some more silly things */
	test_assert(lc_db_set(lctx, NULL, NULL, 0, NULL, 0) == LC_ERROR_DB_REQUIRED,
			"lc_db_set() NULL db => LC_ERROR_DB_REQUIRED");
	test_assert(lc_db_set(lctx, db, NULL, 0, NULL, 0) == LC_ERROR_INVALID_PARAMS,
			"lc_db_set() NULL key => LC_ERROR_INVALID_PARAMS");
	test_assert(lc_db_set(lctx, db, key, 0, NULL, 0) == LC_ERROR_INVALID_PARAMS,
			"lc_db_set() keylen < 1 => LC_ERROR_INVALID_PARAMS");

	/* write something important */
	test_assert(lc_db_set(lctx, db, key, strlen(key), val, strlen(val)) == 0,
				"lc_db_set()");
	/* read it back */
	test_assert(lc_db_get(lctx, db, (void *)key, strlen(key), &vptr, &vlen) == 0,
				"lc_db_get()");
	/* check we read back wot we wrote */
	test_expectn(val, (char *)vptr, vlen);
	free(vptr);
	lc_ctx_free(lctx);
	return fails;
}
