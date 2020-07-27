#include "test.h"
#include "../src/errors.h"
#include "../src/log.h"
#include <stdlib.h>

int main()
{
	test_name("lc_channel_getval()");
	LOG_LEVEL = 127;

	lc_ctx_t *lctx = lc_ctx_new();
	lc_socket_t *sock = lc_socket_new(lctx);
	lc_channel_t *chan = lc_channel_new(lctx, "example.com");
	lc_val_t key, val;
	memset(&key, 0, sizeof(lc_val_t));
	memset(&val, 0, sizeof(lc_val_t));

	test_assert(lc_channel_getval(NULL, NULL, NULL) == LC_ERROR_CHANNEL_REQUIRED,
			"lc_channel_getval() requires channel");
	test_assert(lc_channel_getval(chan, NULL, NULL) == LC_ERROR_INVALID_PARAMS,
			"lc_channel_getval() requires key");
	test_assert(lc_channel_getval(chan, &key, NULL) == LC_ERROR_INVALID_PARAMS,
			"lc_channel_getval() requires key.size > 0");
	char keydata[] = "0000-0017";
	key.data = keydata;
	key.size = strlen(keydata);
	test_assert(lc_channel_getval(chan, &key, NULL) == LC_ERROR_INVALID_PARAMS,
			"lc_channel_getval() requires key.size > 0");

	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);

	return fails;
}