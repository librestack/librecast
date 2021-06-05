#include "test.h"
#include <librecast/net.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/param.h>

#define CHANNELS 16

int main()
{
	lc_ctx_t *lctx;
	lc_channel_t *chan[CHANNELS];
	struct in6_addr *bin6 = NULL, *sin6 = NULL;

	test_name("lc_channel_random()");

	lctx = lc_ctx_new();
	test_assert(lctx != NULL, "lc_ctx_new()");
	if (!lctx) return fails;

	for (int i = 0; i < CHANNELS; i++) {
		chan[i] = lc_channel_random(lctx);
		test_assert(chan[i] != NULL, "error creating channel %i", i);
	}
	for (int i = 0; i < CHANNELS; i++) {
		for (int j = i + 1; j < CHANNELS; j++) {
			bin6 = lc_channel_in6addr(chan[i]);
			sin6 = lc_channel_in6addr(chan[j]);
			test_assert(memcmp(sin6->s6_addr, bin6->s6_addr, 16),
					"channels must be different");
		}
	}
	lc_ctx_free(lctx);
	return fails;
}
