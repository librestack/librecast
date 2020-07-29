#include "test.h"
#include <librecast/net.h>
#include <librecast/netdb.h>
#include "../src/errors.h"
#include "../src/log.h"
#include <stdlib.h>

int main()
{
	test_name("lc_channel_setval() - error handling");
	LOG_LEVEL = 127;

	lc_ctx_t *lctx = lc_ctx_new();
	lc_socket_t *sock = lc_socket_new(lctx);
	lc_channel_t *chan = lc_channel_new(lctx, "example.com");
	lc_val_t key, val;
	char keydata[] = "0000-0018";
	char valdata[] = "42";
	memset(&key, 0, sizeof(lc_val_t));
	memset(&val, 0, sizeof(lc_val_t));

	test_assert(lc_channel_setval(NULL, NULL, NULL) == LC_ERROR_CHANNEL_REQUIRED,
			"lc_channel_setval() requires channel");
	test_assert(lc_channel_setval(chan, NULL, NULL) == LC_ERROR_INVALID_PARAMS,
			"lc_channel_setval() requires key");
	key.data = keydata;
	test_assert(lc_channel_setval(chan, &key, NULL) == LC_ERROR_INVALID_PARAMS,
			"lc_channel_setval() requires key.size > 0");

	key.size = strlen(keydata);
	key.data = NULL;
	test_assert(lc_channel_setval(chan, &key, NULL) == LC_ERROR_INVALID_PARAMS,
			"lc_channel_setval() requires key.data");

	lc_channel_bind(sock, chan);

	key.data = keydata;
	test_assert(lc_channel_setval(chan, &key, NULL) == LC_ERROR_INVALID_PARAMS,
			"lc_channel_setval() requires val");
	val.data = valdata;
	test_assert(lc_channel_setval(chan, &key, &val) == LC_ERROR_INVALID_PARAMS,
			"lc_channel_setval() val.size > 0");
	val.size = strlen(valdata);
	val.data = NULL;
	test_assert(lc_channel_setval(chan, &key, &val) == LC_ERROR_INVALID_PARAMS,
			"lc_channel_setval() val.data != NULL");
	val.data = valdata;
	test_assert(lc_channel_setval(chan, &key, &val) == 0,
			"lc_channel_setval() valid key and data");

	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);

	return fails;
}
