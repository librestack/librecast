#include <arpa/inet.h>
#include <errno.h>
#include <linux/in6.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "config.h"
#include "errors.h"
#include "handler.h"
#include "log.h"
#include "net.h"

int sock;
struct addrinfo *castaddr = NULL;

int net_free()
{
	if (castaddr != NULL)
		freeaddrinfo(castaddr);
	castaddr = NULL;
	return 0;
}

int net_multicast_getaddrinfo(const char *node, const char *service,
		struct addrinfo **res)
{
	struct addrinfo hints = { 0 };
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_NUMERICHOST;
        logmsg(LOG_DEBUG, "resolving multicast address");
        return getaddrinfo(node, service, &hints, res);
}

int net_multicast_init()
{
	int e = 0, errsv;
	char *addr = config_get("castaddr");
	char *port = config_get("castport");
	int publicsrc = config_get_num("publicsrc");
	int value;

        logmsg(LOG_DEBUG, "initializing multicast on %s", addr);

	/* resolve destination address */
	if (net_multicast_getaddrinfo(addr, port, &castaddr) != 0) {
                goto net_multicast_init_fail;
        }

        /* create socket */
        logmsg(LOG_DEBUG, "creating datagram socket");
        sock = socket(castaddr->ai_family, castaddr->ai_socktype, 0);
        if (sock == -1) {
                goto net_multicast_init_fail;
        }

        if (publicsrc == 1) {
		/* request public source address, avoiding privacy extensions */
		value = IPV6_PREFER_SRC_PUBLIC;
		setsockopt(sock, IPPROTO_IPV6, IPV6_ADDR_PREFERENCES, &value,
				sizeof(value));
	}

	if ((e = net_multicast_setoptions()) != 0)
		goto net_multicast_init_fail;

	return 0;

net_multicast_init_fail:
	errsv = errno;
	print_error(e, errsv, "net_multicast_init");
	config_free();
	_exit(e);
}

void *net_multicast_listen()
{
	int e = 0, errsv;
	struct addrinfo *res;
	char *addr = config_get("castaddr");
	char *port = config_get("castport");
	struct addrinfo hints = { 0 };
	struct addrinfo *localaddr;
	struct ipv6_mreq req;

	if (net_multicast_getaddrinfo(addr, port, &res) != 0) {
                goto net_multicast_listen_fail;
        }

	hints.ai_family = res->ai_family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	/* find local address to bind to */
	if (getaddrinfo(NULL, port, &hints, &localaddr) != 0) {
                goto net_multicast_listen_fail;
	}

	/* create datagram socket */
	sock = socket(localaddr->ai_family, localaddr->ai_socktype, 0);
	if (sock == -1) {
                goto net_multicast_listen_fail;
	}

	net_multicast_setoptions();

	/* bind to multicast port */
	if (bind(sock, localaddr->ai_addr, localaddr->ai_addrlen) != 0) {
                goto net_multicast_listen_fail;
	}

	memcpy(&req.ipv6mr_multiaddr,
			&((struct sockaddr_in6*)(res->ai_addr))->sin6_addr,
			sizeof(req.ipv6mr_multiaddr));

	/* ifindex = if_nametoindex("eth0"); */
	req.ipv6mr_interface = 0; /* default interface */

	/* join multicast */
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&req,
				sizeof(req)) != 0)
	{
                goto net_multicast_listen_fail;
	}

	freeaddrinfo(localaddr);
	freeaddrinfo(res);

	for (;;) {
		char recv[1024];
		int l;
		struct sockaddr_storage src_addr;
		socklen_t addrlen;
		char s[INET6_ADDRSTRLEN];

		if ((l = recvfrom(sock, recv, sizeof(recv)-1, 0,
			(struct sockaddr *)&src_addr, &addrlen)) < 0)
		{
			e = ERROR_NET_RECV;
			goto net_multicast_listen_fail;
		}
		recv[l] = '\0';
		inet_ntop(src_addr.ss_family,
			&(((struct sockaddr_in6*)(struct sockaddr *)&src_addr)->sin6_addr),
			s, sizeof s);

		handler_handle_request(recv, s);
	}

	logmsg(LOG_DEBUG, "Barney");
	pthread_exit(&e);

net_multicast_listen_fail:
	errsv = errno;
	print_error(e, errsv, "net_multicast_listen");
	config_free();
	logmsg(LOG_DEBUG, "Fred");
	pthread_exit(&e);
}

int net_multicast_setoptions()
{
	int e = 0;
        int loop = (int)config_get_num("loop");
        int ttl = (int)config_get_num("ttl");

        logmsg(LOG_DEBUG, "setting multicast TTL=%i", ttl);
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl,
                                sizeof(ttl)) != 0)
        {
                e = ERROR_NET_SOCKOPT;
        }

        logmsg(LOG_DEBUG, "setting multicast loopback=%i", loop);
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop,
                                sizeof(loop)) != 0)
        {
                e = ERROR_NET_SOCKOPT;
        }

	return e;
}

int net_multicast_send(char *msg, size_t len)
{
	int e = 0, errsv;

	logmsg(LOG_DEBUG, "Sending datagram");
	if (sendto(sock, msg, len, 0, castaddr->ai_addr, castaddr->ai_addrlen) <
			0)
	{
		goto net_multicast_send_fail;
	}

	return 0;

net_multicast_send_fail:
	errsv = errno;
	print_error(e, errsv, "net_multicast_init");
	net_free();
	return ERROR_NET_SEND;
}


void net_pack(net_header_t h, char buf[16])
{
	uint32_t i32;
	uint64_t i64;
	static uint32_t seq = 0;

	h.seq = seq++;
	h.timestamp = time(NULL);
	i32 = htonl(h.seq);
	memcpy(buf+0, &i32, 4);
	i64 = htonll(h.timestamp);
	memcpy(buf+4, &i64, 8);
	i32 = htonl(h.cmd);
	memcpy(buf+12, &i32, 4);
}

void net_unpack(net_header_t *h, char buf[16])
{
	uint32_t i32;
	uint64_t i64;

	memcpy(&i32, buf+0, 4);
	h->seq = ntohl(i32);
	memcpy(&i64, buf+4, 8);
	h->timestamp = ntohll(i64);
	memcpy(&i32, buf+12, 4);
	h->cmd = ntohl(i32);
}
