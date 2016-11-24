#ifndef __LIBRECAST_NET_H__
#define __LIBRECAST_NET_H__ 1

/* prepare multicast socket for sending */
int net_multicast_init();

/* resolve multicast address. call net_free() when done */
int net_multicast_getaddrinfo(const char *node, const char *service,
		struct addrinfo **res);

/* send multicast message */
int net_multicast_send(char *msg);

/* free memory */
int net_free();

#endif /* __LIBRECAST_NET_H__ */
