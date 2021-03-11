#include "test.h"
#include "../include/librecast/if.h"
#include <sys/types.h>
#include <unistd.h>

int main()
{
	char tapname[IFNAMSIZ];

	test_require_linux();
	test_cap_require(CAP_NET_ADMIN);
	test_name("lc_tap_create()");

	test_assert(lc_tap_create(tapname) > 0, "lc_tap_create - created");
	test_assert(if_nametoindex(tapname) > 0, "check idx, ensure tap exists");

	return fails;
}
