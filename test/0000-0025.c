#include "test.h"
#include <librecast/net.h>
#include <sys/types.h>
#include <sys/param.h>

void dumpaddr(struct in6_addr *addr)
{
	for (int i = 0; i < 128; i++) {
		fprintf(stderr, "%u", !!isset(addr->s6_addr, i));
	}
	fputc('\n', stderr);
}

int main()
{
	union {
		uint64_t u64[2];
		uint8_t u8[16];
		struct in6_addr in6;
	} addrside;
	lc_ctx_t *lctx;
	lc_channel_t *base, *side;
	unsigned pop;

	test_name("lc_channel_sideband()");

	lctx = lc_ctx_new();
	test_assert(lctx != NULL, "lc_ctx_new()");

	base = lc_channel_new(lctx, "freedom");
	test_assert(base != NULL, "lc_channel_new() - create base channel");
	memcpy(&addrside, &lc_channel_sockaddr(base)->sin6_addr, 16);
	dumpaddr(&addrside.in6);

	/* lower side band (zero lower 64 bits) */
	test_assert((side = lc_channel_sideband(base, 0)) != NULL,
			"lc_channel_sideband() - lower sideband");

	memcpy(&addrside, &lc_channel_sockaddr(side)->sin6_addr, 16);
	dumpaddr(&addrside.in6);
	pop = 0;
	for (int i = 8; i < 16; i++) {
		pop += __builtin_popcount(addrside.u8[i]);
	}
	test_assert(!pop, "lower side band - lower 64 bits zeroed, pop=%u", pop);

	/* upper side band (lower 64 bits -> 1) */
	test_assert((side = lc_channel_sideband(base, UINT64_MAX)) != NULL,
			"lc_channel_sideband() - lower sideband");

	memcpy(&addrside, &lc_channel_sockaddr(side)->sin6_addr, 16);
	dumpaddr(&addrside.in6);
	pop = 0;
	for (int i = 8; i < 16; i++) {
		pop += __builtin_popcount(addrside.u8[i]);
	}
	test_assert(pop == 64, "upper side band - lower 64 bits => 1, pop=%u", pop);

	lc_ctx_free(lctx);
	return fails;
}
