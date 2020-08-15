#include "test.h"
#include <librecast/net.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

int main()
{
	test_name("lc_channel_init() / lc_channel_addrinfo()");

	char service[] = "4242";
	char addr_in[] = "ff3e:6d38:646e:b0a8:38ca:8bdb:d839:d788";
	char addr_out[INET6_ADDRSTRLEN];
	struct addrinfo *res;
	lc_ctx_t *lctx;
	lc_channel_t *chan;

	lctx = lc_ctx_new();
	chan = lc_channel_init(lctx, addr_in, service);
	res = lc_channel_addrinfo(chan);
	getnameinfo(res->ai_addr, res->ai_addrlen, addr_out, INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST);
	test_expect(addr_in, addr_out);
	lc_channel_free(chan);
	lc_ctx_free(lctx);

	return fails;
}
