#ifndef __LIBRECAST_SOCKET_H__
#define __LIBRECAST_SOCKET_H__ 1

/* create unix socket */
int socket_bind();

/* close unix socket */
void socket_close();

/* connect to unix socket */
int socket_connect();

/* get name of local socket for client <-> daemon comms */
char *getsockfilename();

#endif /* __LIBRECAST_SOCKET_H__ */
