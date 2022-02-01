#include "test.h"
#include <librecast/if.h>
#include <unistd.h>

int main()
{
	char dev[IFNAMSIZ] = "";
	char *testdev = "testdev";
	char *testdyn = "testdev%d";
	int fd;

	test_require_linux();
	test_cap_require(CAP_NET_ADMIN);
	test_name("lc_tuntap_create()");

	/* blank device name => tun%d */
	if (!test_assert((fd = lc_tuntap_create(dev, IFF_TUN)) > 0, "lc_tuntap_create()"))
		perror("lc_tuntap_create()");

	test_log("interface name: %s", dev);
	close(fd);

	/* use device name if supplied */
	strcpy(dev, testdev);
	if (!test_assert((fd = lc_tuntap_create(dev, IFF_TUN)) > 0, "lc_tuntap_create()"))
		perror("lc_tuntap_create()");
	test_strcmp(dev, testdev, "interface name %s", dev);
	test_log("interface name: %s", dev);
	close(fd);

	/* test dynamically numbered (%d format string) devicename */
	strcpy(dev, testdyn);
	if (!test_assert((fd = lc_tuntap_create(dev, IFF_TUN)) > 0, "lc_tuntap_create()"))
		perror("lc_tuntap_create()");
	test_strcmp(dev, "testdev0", "interface name %s", dev);
	test_log("interface name: %s", dev);
	close(fd);

	return fails;
}
