#include "test.h"
#include "../include/librecast/net.h"
#include "../include/librecast/if.h"
#include <sys/types.h>
#include <unistd.h>

int main()
{
	const char brname[] = "0000-0032";
	enum { tapcount = 42 };
	char tap[tapcount][IFNAMSIZ];
	lc_ctx_t *lctx = NULL;

	test_cap_require(CAP_NET_ADMIN);
	test_name("lc_bridge_addif() / lc_bridge_delif()");

	lctx = lc_ctx_new();
	test_assert(lctx != NULL, "lc_ctx_new()");
	if (!lctx) return fails;

	test_assert(lc_bridge_add(lctx, brname) == 0, "lc_bridge_add()");

	for (int i = 0; i < tapcount; i++) {
		test_assert(lc_tap_create(tap[i]) > 0,
				"lc_tap_create - created (%i)", i);
		test_assert(if_nametoindex(tap[i]) > 0,
				"check idx, ensure tap exists (%i)", i);
		test_assert(lc_link_set(lctx, tap[i], LC_IF_UP) == 0,
			"bring up interface %s (%i)", tap[i], i);
	}

	test_assert(lc_bridge_addif(lctx, "Scottish Mist", tap[0]) == ENODEV,
			"lc_bridge_addif() - missing bridge", tap[0]);

	test_assert(lc_bridge_addif(lctx, brname, "faildev") == ENODEV,
			"lc_bridge_addif() - missing interface");

	test_assert(lc_bridge_delif(lctx, brname, tap[0]) != 0,
			"lc_bridge_delif() - try to delete if we haven't added");

	for (int i = 0; i < tapcount; i++) {
		test_assert(lc_bridge_addif(lctx, brname, tap[i]) == 0,
			"lc_bridge_addif() - %s (%i)", tap[i], i);
	}

	for (int i = 0; i < tapcount; i++) {
		test_assert(lc_bridge_delif(lctx, brname, tap[i]) == 0,
			"lc_bridge_delif() - delete if %i", i);
	}

	test_assert(lc_bridge_del(lctx, brname) == 0, "lc_bridge_del()");
	lc_ctx_free(lctx);

	return fails;
}
