#include "test.h"
#include <librecast/net.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <ifaddrs.h>

int gotmsg = 0;

void sighandler(int sig)
{
	test_log("caught signal %i", sig);
}

void msg_received(lc_message_t *msg)
{
	(void)msg;
	test_log("message received");
	gotmsg = 1;
	kill(getpid(), SIGINT);
}

int main()
{
	lc_ctx_t *lctx = NULL;
	lc_socket_t *sock = NULL;
	lc_channel_t *chan = NULL;
	lc_message_t msg;
	struct ifaddrs *ifaddr, *ifa;

	test_name("multicast ping (loopback disabled)");

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	chan = lc_channel_new(lctx, "example.com");

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

	test_assert(!lc_channel_bind(sock, chan), "lc_channel_bind()");
	test_assert(!lc_channel_join(chan), "lc_channel_join()");
	test_assert(!lc_socket_listen(sock, msg_received, NULL), "lc_socket_listen()");

	/* send packet with loopback turned off */
	char *data = "BLACK LIVES MATTER";
	lc_msg_init_data(&msg, data, strlen(data), NULL, NULL);
	signal(SIGINT, sighandler);
	lc_msg_send(chan, &msg);

	struct timespec t;
	t.tv_sec = 0;
	t.tv_nsec = 99999999;
	nanosleep(&t, &t);
	test_assert(!gotmsg, "received loopback message when loopback disabled");

	test_assert(!lc_socket_listen_cancel(sock), "lc_socket_listen_cancel()");
	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);

	return fails;
}
