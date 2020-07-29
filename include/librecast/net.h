/*
 * librecast.h - The librecast API
 * 
 */

#ifndef _LIBRECAST_NET_H
#define _LIBRECAST_NET_H

#include <librecast/types.h>

/* create new librecast context and set up environment */
lc_ctx_t * lc_ctx_new();

/* manage message structures */
void *lc_msg_init(lc_message_t *msg);
int lc_msg_init_size(lc_message_t *msg, size_t len);
int lc_msg_init_data(lc_message_t *msg, void *data, size_t len, void *f, void *hint);
void lc_msg_free(void *msg);
int lc_msg_get(lc_message_t *msg, lc_msg_attr_t attr, void *value);
int lc_msg_set(lc_message_t *msg, lc_msg_attr_t attr, void *value);

void lc_msglist_free(lc_messagelist_t *msg);

/* return pointer to message payload */
void *lc_msg_data(lc_message_t *msg);

/* open database */
int lc_db_open(lc_ctx_t *ctx, char *dbpath);

/* fetch a single key */
int lc_db_get(lc_ctx_t *ctx, const char *db, void *key, size_t klen, void **val, size_t *vlen);

/* set key/val in named database db */
int lc_db_set(lc_ctx_t *ctx, const char *db, void *key, size_t klen, void *val, size_t vlen);

/* as lc_db_set(), respecting database modes  */
int lc_db_set_mode(lc_ctx_t *ctx, const char *db, void *key, size_t klen, void *val, size_t vlen, int mode);

/* set key/val index */
int lc_db_idx(lc_ctx_t *ctx, const char *left, const char *right, void *key, size_t klen, void *val, size_t vlen, int mode);

/* query functions */
int lc_query_new(lc_ctx_t *ctx, lc_query_t **q);
void lc_query_free(lc_query_t *q);
int lc_query_push(lc_query_t *q, lc_query_op_t op, void *data);
int lc_query_exec(lc_query_t *q, lc_messagelist_t **msg);

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
int lc_hashgroup(char *baseaddr, char *groupname, char *hashaddr, unsigned int flags);

/* data storage functions */
int lc_getval(lc_val_t *key, lc_val_t *val);
int lc_setval(lc_val_t *key, lc_val_t *val);
int lc_channel_getval(lc_channel_t *chan, lc_val_t *key);
int lc_channel_setval(lc_channel_t *chan, lc_val_t *key, lc_val_t *val);

/* destroy librecast context and clean up */
void lc_ctx_free(lc_ctx_t *ctx);

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
lc_channel_t * lc_channel_new(lc_ctx_t *ctx, char * url);

/* bind channel to socket */
int lc_channel_bind(lc_socket_t *sock, lc_channel_t * channel);

/* find channel from address */
lc_channel_t * lc_channel_by_address(char addr[INET6_ADDRSTRLEN]);

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

/* join multicast group by address
 * src can be NULL for ASM mode, or a valid source address for SSM */
int lc_joingroupbyaddr(unsigned char *addr, char *src);

/* join named multicast group
 * groupname is hashed and XORed with the base multicast address
 * src can be NULL for ASM mode, or a valid source address for SSM */
int lc_joingroupbyname(char*groupname, char *src);

/* get some random bytes */
int lc_getrandom(void *buf, size_t buflen, unsigned int flags);

#endif /* _LIBRECAST_NET_H */
