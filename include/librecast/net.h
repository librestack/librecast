/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2017-2021 Brett Sheffield <bacs@librecast.net> */
/* librecast/net.h - librecast network API */

#ifndef _LIBRECAST_NET_H
#define _LIBRECAST_NET_H

#include <librecast/types.h>

extern int (*lc_msg_logger)(lc_channel_t *, lc_message_t *, void *logdb);

/* create new librecast context and set up environment
 * call lc_ctx_free() when done */
lc_ctx_t *lc_ctx_new();

/* destroy librecast context and clean up */
void lc_ctx_free(lc_ctx_t *ctx);

/* create librecast socket */
lc_socket_t *lc_socket_new(lc_ctx_t *ctx);

/* bind socket to interface with index idx. 0 = ALL (default) */
int lc_socket_bind(lc_socket_t *sock, unsigned int ifx);

/* close socket */
void lc_socket_close(lc_socket_t *sock);

/* Create a new channel by hashing s of length len */
lc_channel_t *lc_channel_nnew(lc_ctx_t *ctx, unsigned char *s, size_t len);

/* Create a new channel from the hash of s which must be a NUL-terminated string */
lc_channel_t *lc_channel_new(lc_ctx_t *ctx, char *s);

/* copy a channel into ctx */
lc_channel_t *lc_channel_copy(lc_ctx_t *ctx, lc_channel_t *chan);

/* create side band channel from base channel by replacing lower 64 bits with band */
lc_channel_t * lc_channel_sideband(lc_channel_t *base, uint64_t band);

/* create side channel from base by hashing additional key material */
lc_channel_t * lc_channel_sidehash(lc_channel_t *base, unsigned char *key, size_t keylen);

/* create random channel */
lc_channel_t *lc_channel_random(lc_ctx_t *ctx);

/* bind channel to socket */
int lc_channel_bind(lc_socket_t *sock, lc_channel_t *chan);

/* unbind channel from socket */
int lc_channel_unbind(lc_channel_t *chan);

/* join librecast channel */
int lc_channel_join(lc_channel_t *chan);

/* leave a librecast channel */
int lc_channel_part(lc_channel_t *chan);

/* blocking socket recv() */
ssize_t lc_socket_recv(lc_socket_t *sock, void *buf, size_t len, int flags);

/* non-blocking socket listener, with callbacks */
int lc_socket_listen(lc_socket_t *sock, void (*callback_msg)(lc_message_t*),
			                void (*callback_err)(int));

/* stop listening on socket */
int lc_socket_listen_cancel(lc_socket_t *sock);

/* send to all channels bound to a socket */
ssize_t lc_socket_send(lc_socket_t *sock, const void *buf, size_t len, int flags);
ssize_t lc_socket_sendmsg(lc_socket_t *sock, struct msghdr *msg, int flags);

/* send to channel. Channel must be bound to Librecast socket with
 * lc_channel_bind() first. */
ssize_t lc_channel_send(lc_channel_t *chan, const void *buf, size_t len, int flags);
ssize_t lc_channel_sendmsg(lc_channel_t *chan, struct msghdr *msg, int flags);

/* blocking message receive */
ssize_t lc_msg_recv(lc_socket_t *sock, lc_message_t *msg);
ssize_t lc_socket_recvmsg(lc_socket_t *sock, struct msghdr *msg, int flags);

/* send a message to a channel */
ssize_t lc_msg_send(lc_channel_t *chan, lc_message_t *msg);
ssize_t lc_msg_sendto(int sock, const void *buf, size_t len, struct sockaddr_in6 *addr, int flags);

/* get/set socket options */
int lc_socket_getopt(lc_socket_t *sock, int optname, void *optval, socklen_t *optlen);
int lc_socket_setopt(lc_socket_t *sock, int optname, const void *optval, socklen_t optlen);

/* turn socket loopback on (val = 1) or off (val = 0)*/
int lc_socket_loop(lc_socket_t *sock, int val);

/* set multicast TTL (hop limit) for this socket to val */
int lc_socket_ttl(lc_socket_t *sock, int val);

/* manage message structures */

/* initialize message structure */
void *lc_msg_init(lc_message_t *msg);

/* allocate message struture of size len */
int lc_msg_init_size(lc_message_t *msg, size_t len);

/* initialize message from supplied data of size len
 * if not NULL, function f will be called to free the structure with hint as an argument */
int lc_msg_init_data(lc_message_t *msg, void *data, size_t len, lc_free_fn_t *f, void *hint);

/* free message */
void lc_msg_free(void *msg);

/* hash message data and source address
 * call with pre-allocated buffer id of size len */
int lc_msg_id(lc_message_t *msg, unsigned char *id, size_t len);

/* return pointer to message data */
void *lc_msg_data(lc_message_t *msg);

/* get message attributes */
int lc_msg_get(lc_message_t *msg, lc_msg_attr_t attr, void **value);

/* set message attributes */
int lc_msg_set(lc_message_t *msg, lc_msg_attr_t attr, void *value);

/* access structure internals */

/* return structure ids */
uint32_t lc_ctx_get_id(lc_ctx_t *ctx);
uint32_t lc_socket_get_id(lc_socket_t *sock);
uint32_t lc_channel_get_id(lc_channel_t *chan);

/* return raw network socket */
int lc_socket_raw(lc_socket_t *sock);
int lc_channel_socket_raw(lc_channel_t *chan);

/* return context for channel chan */
lc_ctx_t *lc_channel_ctx(lc_channel_t *chan);

/* return socket bound to this channel */
lc_socket_t *lc_channel_socket(lc_channel_t *chan);

/* return socket address for this channel */
struct sockaddr_in6 *lc_channel_sockaddr(lc_channel_t *chan);

/* return struct in6_addr for this channel */
struct in6_addr *lc_channel_in6addr(lc_channel_t *chan);

/* return channel uri */
char *lc_channel_uri(lc_channel_t *chan);

/* create new channel from grp address and service */
lc_channel_t * lc_channel_init(lc_ctx_t *ctx, struct sockaddr_in6 *sa);

/* free channel */
void lc_channel_free(lc_channel_t *chan);

/* get some random bytes */
int lc_getrandom(void *buf, size_t buflen);

#endif /* _LIBRECAST_NET_H */
