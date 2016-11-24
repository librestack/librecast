#ifndef __LIBRECAST_NET_H__
#define __LIBRECAST_NET_H__ 1

int net_multicast_init();
int net_multicast_send(char *msg);
int net_free();

#endif /* __LIBRECAST_NET_H__ */
