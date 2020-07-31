#include "test.h"
#include <librecast/net.h>
#include <librecast/db.h>
#include "../src/errors.h"
#include "../src/log.h"

int main()
{
	test_name("lc_query_new() / lc_query_free() / lc_query_push()");
	LOG_LEVEL = 127;
	lc_ctx_t *lctx;
	lc_channel_t *chan;
	lc_query_t *q = NULL;
	lc_message_t msg[4];
	lc_messagelist_t *msglist = NULL, *m = NULL;
	char dbpath[] = "0000-0022.tmp.XXXXXX";
	char chanuri[] = "example.com";
	char *freedom[4];
	freedom[0] = "The freedom to run the program as you wish, for any purpose";
	freedom[1] = "The freedom to study how the program works, and change it";
	freedom[2] = "The freedom to redistribute copies so you can help your neighbor";
	freedom[3] = "The freedom to distribute copies of your modified versions to others";
	int msgs = 0;

	lctx = lc_ctx_new();
	chan = lc_channel_new(lctx, chanuri);

	/* initialize messages */
	for (int i = 0; i < 4; i++) {
		lc_msg_init_data(&msg[i], freedom[i], strlen(freedom[i]), NULL, NULL);
		msg[i].timestamp = i; /* timestamp required for msg ordering */
	}

	test_assert(lc_query_new(NULL, &q) == LC_ERROR_CTX_REQUIRED,
		"lc_query_new(): NULL ctx");
	test_assert(lc_query_new(lctx, &q) == LC_ERROR_DB_REQUIRED,
		"lc_query_new(): no database");
	test_assert(lc_db_open(lctx, mkdtemp(dbpath)) == 0,
		"lc_db_open() - open temp db");
	test_assert((msgs = lc_query_exec(NULL, &msglist)) == -1,
		"no query");
	test_assert(lc_query_new(lctx, &q) == 0,
		"lc_query_new() (1)");
	test_assert(lc_query_push(NULL, LC_QUERY_EQ, freedom[0]) == LC_ERROR_INVALID_PARAMS,
		"lc_query_push(): NULL query");
	test_assert(lc_query_push(q, LC_QUERY_NOOP, freedom[0]) == 0,
		"lc_query_push() NOOP");
	test_assert((msgs = lc_query_exec(q, &msglist)) == 0,
		"no msgs found");
	test_log("msgs = %i", msgs);
	lc_query_free(q);

	/* log some messages */
	for (int i = 0; i < 4; i++) {
		test_log("[%i] logmsg '%s'", i, msg[i].data);
		test_expect(freedom[i], msg[i].data);
		test_assert(lc_channel_logmsg(chan, &msg[i]) == 0, "lc_channel_logmsg()[%i]", i);
	}

	/* fetch all messages */
	test_assert(lc_query_new(lctx, &q) == 0, "lc_query_new() (2)");
	test_assert((msgs = lc_query_exec(q, &msglist)) == 4, "query (2), 4 msgs found");
	test_log("msgs = %i", msgs);

	/* verify message text */
	m = msglist;
	for (int i = 0; i < 4; i++) {
		test_log("[%i] '%s'", i, freedom[i]);
		test_log("[%i] '%s'", i, m->data);
		test_expect(freedom[i], m->data);
		m = m->next;
	}
	lc_msglist_free(msglist);
	msglist = NULL;
	lc_query_free(q);

	/* TODO apply message filters */

	lc_channel_free(chan);
	lc_ctx_free(lctx);
	return fails;
}
