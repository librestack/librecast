#ifndef __LIBRECAST_SOCKET_H__
#define __LIBRECAST_SOCKET_H__ 1

/* create unix socket */
int socket_bind();

/* close unix socket */
void socket_close();

/* connect to unix socket */
int socket_connect();

/* non-blocking read from socket */
int socket_read(char *buf);

/* write to all connected local unix sockets */
int socket_send(char *buf, size_t len);

/* get name of local socket for client <-> daemon comms */
char *getsockfilename();

#endif /* __LIBRECAST_SOCKET_H__ */
