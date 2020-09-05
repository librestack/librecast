/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2017-2020 Brett Sheffield <bacs@librecast.net> */
/* librecast/net.h - librecast network API */

#ifndef _LIBRECAST_NET_H
#define _LIBRECAST_NET_H

#include <librecast/types.h>
#include <openssl/sha.h>

/* create new librecast context and set up environment
 * call lc_ctx_free() when done */
lc_ctx_t * lc_ctx_new();

/* destroy librecast context and clean up */
void lc_ctx_free(lc_ctx_t *ctx);

/* manage message structures */
void *lc_msg_init(lc_message_t *msg);
int lc_msg_init_size(lc_message_t *msg, size_t len);
int lc_msg_init_data(lc_message_t *msg, void *data, size_t len, void *f, void *hint);
void lc_msg_free(void *msg);
int lc_msg_get(lc_message_t *msg, lc_msg_attr_t attr, void **value);
int lc_msg_set(lc_message_t *msg, lc_msg_attr_t attr, void *value);
int lc_msg_id(lc_message_t *msg, unsigned char id[SHA_DIGEST_LENGTH]);

/* return pointer to message payload */
void *lc_msg_data(lc_message_t *msg);

/* convert opcode to text */
char *lc_opcode_text(lc_opcode_t op);

/* return structure ids */
uint32_t lc_ctx_get_id(lc_ctx_t *ctx);
uint32_t lc_socket_get_id(lc_socket_t *sock);
uint32_t lc_channel_get_id(lc_channel_t *chan);

/* bridge and interface functions */
int lc_bridge_init();
int lc_bridge_new(char *brname);
int lc_bridge_add_interface(const char *brname, const char *ifname);
int lc_link_set(char *ifname, int flags);
int lc_tap_create(char **ifname);

/* create multicast group address from baseaddr and hash of groupname */
int lc_hashgroup(char *baseaddr, unsigned char *group, size_t len, char *hashaddr, unsigned int flags);

/* create librecast socket */
lc_socket_t *lc_socket_new(lc_ctx_t *ctx);

/* get/set socket options */
int lc_socket_getopt(lc_socket_t *sock, int optname, void *optval, socklen_t *optlen);
int lc_socket_setopt(lc_socket_t *sock, int optname, const void *optval, socklen_t optlen);

/* non-blocking socket listener, with callbacks */
int lc_socket_listen(lc_socket_t *sock, void (*callback_msg)(lc_message_t*),
			                void (*callback_err)(int));

/* stop listening on socket */
int lc_socket_listen_cancel(lc_socket_t *sock);

/* close socket */
void lc_socket_close(lc_socket_t *sock);

/* create new channel from group address */
lc_channel_t * lc_channel_init(lc_ctx_t *ctx, char * grpaddr, char * service);

/* create a new channel handle from url */
lc_channel_t * lc_channel_nnew(lc_ctx_t *ctx, unsigned char * uri, size_t len);
lc_channel_t * lc_channel_new(lc_ctx_t *ctx, char * url);

/* bind channel to socket */
int lc_channel_bind(lc_socket_t *sock, lc_channel_t * channel);

/* return addrinfo structure for channel */
struct addrinfo * lc_channel_addrinfo(lc_channel_t * channel);

/* find channel from address */
lc_channel_t * lc_channel_by_address(lc_ctx_t *ctx, char addr[INET6_ADDRSTRLEN]);

/* return librecast context for channel */
lc_ctx_t *lc_channel_ctx(lc_channel_t *chan);

/* return channel URI */
char *lc_channel_uri(lc_channel_t *chan);

/* unbind channel from socket */
int lc_channel_unbind(lc_channel_t * channel);

/* join librecast channel */
int lc_channel_join(lc_channel_t * channel);

/* leave a librecast channel */
int lc_channel_part(lc_channel_t * channel);

/* free channel */
int lc_channel_free(lc_channel_t * channel);

/* return socket bound to this channel */
lc_socket_t *lc_channel_socket(lc_channel_t * channel);

/* return raw socket bound to this channel */
int lc_channel_socket_raw(lc_channel_t * channel);

/* return raw socket fd for this socket */
int lc_socket_raw(lc_socket_t *sock);

/* blocking message receive */
ssize_t lc_msg_recv(lc_socket_t *sock, lc_message_t *msg);

/* send a message to a channel */
ssize_t lc_msg_send(lc_channel_t *channel, lc_message_t *msg);

ssize_t lc_msg_sendto(int sock, const void *buf, size_t len, struct addrinfo *addr);
ssize_t lc_msg_sendto_all(int sock, const void *buf, size_t len, struct addrinfo *addr);

/* join multicast group by address
 * src can be NULL for ASM mode, or a valid source address for SSM */
int lc_joingroupbyaddr(unsigned char *addr, char *src);

/* join named multicast group
 * groupname is hashed and XORed with the base multicast address
 * src can be NULL for ASM mode, or a valid source address for SSM */
int lc_joingroupbyname(char*groupname, char *src);

/* get some random bytes */
int lc_getrandom(void *buf, size_t buflen);

#endif /* _LIBRECAST_NET_H */
