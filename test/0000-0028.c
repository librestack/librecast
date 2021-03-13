#include "test.h"
#include "../include/librecast/net.h"
#include <unistd.h>
#include <net/if.h>
#include <ifaddrs.h>

static int logged;

int logme(lc_channel_t *chan, lc_message_t *msg, void *logdb)
{
	(void)chan; (void)msg; (void)logdb;
	logged++;
	return 0;
}

void sendmsgs(lc_channel_t *chan, lc_message_t *msg, int msgs)
{
	for (int i = 0; i < msgs; i++) {
		lc_msg_send(chan, msg);
	}
}

int main()
{
	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan;
	lc_message_t msg = {0};
	struct ifaddrs *ifaddr, *ifa;

	test_name("lc_msg_logger()");

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	chan = lc_channel_new(lctx, "channel logger");

	/* find first interface that supports IPv6 multicast */
	test_assert(getifaddrs(&ifaddr) != -1, "getifaddrs()");
	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
		if ((ifa->ifa_flags & IFF_MULTICAST) == IFF_MULTICAST
		  && ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6)
		{
			lc_socket_bind(sock, if_nametoindex(ifa->ifa_name));
			break;
		}
	}
	freeifaddrs(ifaddr);

	lc_socket_loop(sock, 1);
	lc_channel_bind(sock, chan);
	lc_channel_join(chan);
	lc_socket_listen(sock, NULL, NULL);

	sendmsgs(chan, &msg, 3);

	usleep(1000);

	/* test with no logger */
	test_assert(logged == 0, "(no logger) msgs logged = %i", logged);

	/* set logger */
	lc_msg_logger = &logme;

	logged = 0;
	sendmsgs(chan, &msg, 7);

	usleep(1000);

	test_assert(logged == 7, "(msg logger set) msgs logged = %i", logged);

	lc_ctx_free(lctx);

	return fails;
}
