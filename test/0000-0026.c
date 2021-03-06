#include "test.h"
#include <librecast/net.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/param.h>

void dumpaddr(struct in6_addr *addr)
{
	char straddr[INET6_ADDRSTRLEN] = "";
	inet_ntop(AF_INET6, addr, straddr, INET6_ADDRSTRLEN);
	test_log("%s\n", straddr);
}

int main()
{
	lc_ctx_t *lctx;
	lc_channel_t *base, *side, *rev;
	struct in6_addr *bin6 = NULL, *sin6 = NULL;
	unsigned char key = 42;

	test_name("lc_channel_sidehash()");

	lctx = lc_ctx_new();
	test_assert(lctx != NULL, "lc_ctx_new()");
	if (!lctx) return fails;

	base = lc_channel_new(lctx, "freedom");
	test_assert(base != NULL, "lc_channel_new() - create base channel");
	if (!base) return fails;

	bin6 = lc_channel_in6addr(base);
	test_assert(bin6 != NULL, "lc_channel_sockaddr(base)");
	if (!bin6) return fails;

	test_log("base: ");
	dumpaddr(bin6);
	test_log("base=%p, side=%p", (void *)bin6, (void *)sin6);
	test_assert((side = lc_channel_sidehash(base, &key, sizeof key)) != NULL,
			"lc_channel_sidehash(1)");
	if (!side) return fails;

	sin6 = lc_channel_in6addr(side);
	test_assert(sin6 != NULL, "lc_channel_sockaddr(base)");
	if (!sin6) return fails;

	test_log("side: ");
	dumpaddr(sin6);

	test_assert(lc_channel_sockaddr(base) != lc_channel_sockaddr(side),
			"copy address differs from base");

	test_assert(memcmp(sin6->s6_addr, bin6->s6_addr, 16),
			"side channel and base channel must be different");

	/* make sure side channel of side channel isn't the original channel */
	rev = lc_channel_sidehash(side, &key, sizeof key);
	test_assert(rev != NULL, "lc_channel_sidehash(2)");
	sin6 = &lc_channel_sockaddr(rev)->sin6_addr;
	test_assert(memcmp(sin6->s6_addr, bin6->s6_addr, 16),
			"side side channel and base channel must be different");
	test_log("side(2): ");
	dumpaddr(sin6);

	lc_ctx_free(lctx);
	return fails;
}
