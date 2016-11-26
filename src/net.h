#ifndef __LIBRECAST_NET_H__
#define __LIBRECAST_NET_H__ 1

#include <netdb.h>
#include <stdint.h>

typedef struct {
	uint32_t seq;
	uint64_t timestamp;
	uint32_t cmd;
} net_header_t;

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

/* free memory */
int net_free();

/* pack data for sending */
void net_pack(net_header_t h, char buf[16]);

/* unpack received data */
void net_unpack(net_header_t *h, char buf[16]);

/* resolve multicast address. call net_free() when done */
int net_multicast_getaddrinfo(const char *node, const char *service,
		struct addrinfo **res);

/* prepare multicast socket for sending */
int net_multicast_init();

/* bind and listen to multicast address */
void *net_multicast_listen();

/* send multicast message */
int net_multicast_send(char *msg, size_t len);

/* set multicast socket options */
int net_multicast_setoptions();

#endif /* __LIBRECAST_NET_H__ */
