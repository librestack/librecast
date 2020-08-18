#include "test.h"
#include <librecast/net.h>
#include "../src/log.h"
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if.h>

int main()
{
	test_name("coverity 296303 Copy into fixed size buffer - lc_link_set()");
	LOG_LEVEL = 127;
	const size_t limit = IFNAMSIZ + 1;
	size_t len;

	char *ifname = malloc(limit);
	test_assert(ifname != NULL, "malloc()");
	if (ifname) {
		memset(ifname, 'a', limit);
		ifname[limit - 1] = '\0';
		len = strlen(ifname);
		test_assert(strlen(ifname) >= IFNAMSIZ,
			"limit not long enough to trigger error %zu <= IFNAMSIZ=%zu", len, IFNAMSIZ);

		test_assert(lc_link_set(ifname, 0) == LC_ERROR_INVALID_PARAMS,
			"ifname too long returns LC_ERROR_INVALID_PARAMS");

		free(ifname);
	}
	return fails;
}
