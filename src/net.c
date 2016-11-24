#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <unistd.h>
#include "config.h"
#include "errors.h"
#include "log.h"
#include "net.h"

int sock;
struct addrinfo *castaddr;

int net_multicast_init()
{
	int e = 0, errsv;
        int loop = 1; /* 0 = off, 1 = on (default) */
        int ttl = 1;
	char *addr = config_get("castaddr");
	char *port = config_get("castport");

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

        /* set TTL */
        logmsg(LOG_DEBUG, "setting multicast TTL");
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char *)&ttl,
                                sizeof(ttl)) != 0)
        {
                goto net_multicast_init_fail;
        }

        logmsg(LOG_DEBUG, "setting loopback");
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char *)&loop,
                                sizeof(loop)) != 0)
        {
                goto net_multicast_init_fail;
        }

	return 0;

net_multicast_init_fail:
	errsv = errno;
	print_error(e, errsv, "net_multicast_init");
	config_free();
	_exit(e);
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

int net_multicast_send(char *msg)
{
	int e = 0, errsv;

	logmsg(LOG_DEBUG, "Sending datagram");
	if (sendto(sock, msg, sizeof(char) * strlen(msg) + 1, 0,
				castaddr->ai_addr, castaddr->ai_addrlen) < 0)
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

int net_free()
{
	freeaddrinfo(castaddr);
	return 0;
}
