#include "test.h"
#include "../src/errors.h"
#include "../src/log.h"
#include <stdlib.h>

int main()
{
	test_name("lc_channel_getval() - error handling");
	LOG_LEVEL = 127;

	lc_ctx_t *lctx = lc_ctx_new();
	lc_socket_t *sock = lc_socket_new(lctx);
	lc_channel_t *chan = lc_channel_new(lctx, "example.com");
	lc_val_t key, val;
	char keydata[] = "0000-0017";
	memset(&key, 0, sizeof(lc_val_t));
	memset(&val, 0, sizeof(lc_val_t));

	test_assert(lc_channel_getval(NULL, NULL) == LC_ERROR_CHANNEL_REQUIRED,
			"lc_channel_getval() requires channel");
	test_assert(lc_channel_getval(chan, NULL) == LC_ERROR_INVALID_PARAMS,
			"lc_channel_getval() requires key");
	key.data = keydata;
	test_assert(lc_channel_getval(chan, &key) == LC_ERROR_INVALID_PARAMS,
			"lc_channel_getval() requires key.size > 0");

	key.size = strlen(keydata);
	key.data = NULL;
	test_assert(lc_channel_getval(chan, &key) == LC_ERROR_INVALID_PARAMS,
			"lc_channel_getval() requires key.data");

	lc_channel_bind(sock, chan);

	key.data = keydata;
	test_assert(lc_channel_getval(chan, &key) == 0,
			"lc_channel_getval() ");

	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);

	return fails;
}
