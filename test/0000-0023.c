#include "test.h"
#include <librecast/net.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

int main()
{
	char addr_in[] = "ff3e:6d38:646e:b0a8:38ca:8bdb:d839:d788";
	char addr_out[INET6_ADDRSTRLEN];
	struct sockaddr_in6 sa;
	struct sockaddr_in6 *sar;
	lc_ctx_t *lctx;
	lc_channel_t *chan;

	test_name("lc_channel_init() / lc_channel_sockaddr()");

	lctx = lc_ctx_new();
	inet_pton(AF_INET6, addr_in, &sa.sin6_addr);
	chan = lc_channel_init(lctx, &sa);
	sar = lc_channel_sockaddr(chan);
	inet_ntop(AF_INET6, &sar->sin6_addr, addr_out, INET6_ADDRSTRLEN);
	test_expect(addr_in, addr_out);
	lc_channel_free(chan);
	lc_ctx_free(lctx);

	return fails;
}
