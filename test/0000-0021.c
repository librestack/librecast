#include "test.h"
#include <librecast/net.h>
#include <librecast/db.h>
#include "../src/errors.h"
#include "../src/log.h"

int main()
{
	test_name("lc_channel_logmsg()");
	LOG_LEVEL = 127;
	lc_ctx_t *lctx;
	lc_channel_t *chan;
	lc_message_t msg[4];
	char dbpath[] = "0000-0021.tmp.XXXXXX";
	char chanuri[] = "example.com";
	char *freedom[4];
	freedom[0] = "The freedom to run the program as you wish, for any purpose";
	freedom[1] = "The freedom to study how the program works, and change it";
	freedom[2] = "The freedom to redistribute copies so you can help your neighbor";
	freedom[3] = "The freedom to distribute copies of your modified versions to others";
	unsigned char key[SHA_DIGEST_LENGTH];
	void *val = NULL;
	size_t vlen = 0;
	int res = 0;

	lctx = lc_ctx_new();
	chan = lc_channel_new(lctx, chanuri);

	/* initialize messages */
	for (int i = 0; i < 4; i++) {
		lc_msg_init_data(&msg[i], freedom[i], strlen(freedom[i]), NULL, NULL);
	}

	test_assert(lc_channel_logmsg(NULL, &msg[0]) == LC_ERROR_CHANNEL_REQUIRED,
			"lc_channel_logmsg(): no channel");
	test_assert(lc_channel_logmsg(chan, &msg[0]) == LC_ERROR_DB_REQUIRED,
			"lc_channel_logmsg(): no database");

	test_assert(lc_db_open(lctx, mkdtemp(dbpath)) == 0, "lc_db_open() - open temp db");

	test_assert(lc_channel_logmsg(chan, NULL) == LC_ERROR_MESSAGE_REQUIRED,
			"lc_channel_logmsg(): no msg");

	/* log some messages */
	for (int i = 0; i < 4; i++) {
		test_log("[%i] logmsg '%s'", i, msg[i].data);
		test_expect(freedom[i], msg[i].data);
		test_assert(lc_channel_logmsg(chan, &msg[i]) == 0, "lc_channel_logmsg()[%i]", i);
	}

	/* read back messages */
	for (int i = 0; i < 4; i++) {
		lc_msg_id(&msg[i], (unsigned char *)key);
		test_assert((res = lc_db_get(lctx, "message", (char *)key, SHA_DIGEST_LENGTH,
						&val, &vlen)) == 0, "lc_db_get()");
		test_log("lc_db_get()[%i] returned %i with %zu bytes", i, res, vlen);
		test_expectn(freedom[i], (char *)val, vlen);
		free(val);

		test_assert((res = lc_db_get(lctx, "message_channel", (char *)key, SHA_DIGEST_LENGTH,
						&val, &vlen)) == 0, "lc_db_get()");
		test_expectn(chanuri, (char *)val, vlen);
		free(val);
	}

	/* TODO: check dst, src, timestamp */

	lc_channel_free(chan);
	lc_ctx_free(lctx);
	return fails;
}
