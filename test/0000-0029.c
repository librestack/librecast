#include "test.h"
#include "../include/librecast/net.h"
#include "../include/librecast/if.h"
#include <sys/types.h>
#include <unistd.h>

int main()
{
	const char brname[] = "0000-0029";
	lc_ctx_t *lctx;

	test_require_linux();
	test_cap_require(CAP_NET_ADMIN);
	test_name("lc_bridge_add() / lc_bridge_del()");

	lctx = lc_ctx_new();
	test_assert(lc_bridge_del(lctx, brname) == ENXIO,
		"lc_bridge_del() - try to delete bridge that doesn't exist");
	perror("lc_bridge_del");
	test_assert(lc_bridge_add(lctx, brname) == 0,
		"lc_bridge_add() - add the bridge");
	perror("lc_bridge_add");
	test_assert(lc_bridge_del(lctx, brname) == 0,
		"lc_bridge_del() - now delete it successfully");
	perror("lc_bridge_add");
	test_assert(lc_bridge_del(lctx, brname) == ENXIO,
		"lc_bridge_del() - try to delete it again and fail");
	perror("lc_bridge_del");
	lc_ctx_free(lctx);

	return fails;
}
