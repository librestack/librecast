#include "test.h"
#include "../include/librecast/net.h"
#include "../include/librecast/if.h"
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <sys/ioctl.h>

int sock = -1;

int isup(const char *ifname)
{
	struct ifreq ifr = {0};
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ioctl(sock, SIOCGIFFLAGS, &ifr);
	return ifr.ifr_flags & IFF_UP;
}

int main()
{
	char tapname[IFNAMSIZ];
	lc_ctx_t *lctx = NULL;

	test_require_linux();
	test_cap_require(CAP_NET_ADMIN);
	test_name("lc_link_set()");

	test_assert(lc_tap_create(tapname) > 0, "lc_tap_create - created");
	test_assert(if_nametoindex(tapname) > 0, "check idx, ensure tap exists");

	lctx = lc_ctx_new();
	test_assert(lctx != NULL, "lc_ctx_new()");
	if (!lctx) return fails;

	sock = socket(AF_LOCAL, SOCK_STREAM, 0);
	test_assert(sock != -1, "test socket (AF_LOCAL)");
	if (sock == -1) return fails;

	test_assert(!isup(tapname), "interface is down");

	test_assert(lc_link_set(lctx, tapname, LC_IF_UP) == 0,
			"bring up interface %s", tapname);

	test_assert(isup(tapname), "interface is up");

	test_assert(lc_link_set(lctx, tapname, LC_IF_DOWN) == 0,
			"bring down interface %s", tapname);

	test_assert(!isup(tapname), "interface is down");

	lc_ctx_free(lctx);
	close(sock);

	return fails;
}
