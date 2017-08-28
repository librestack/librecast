/*
 * librecast.h - The librecast API
 * 
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <stdint.h>

#define LIBRECASTD_NOT_RUNNING 0
#define LIBRECASTD_RUNNING 1
#define LC_BRIDGE_NAME "lc0"
#define LC_DATABASE_FILE "/var/cache/librecast.sqlite"

typedef uint64_t lc_seq_t;
typedef uint64_t lc_rnd_t;
typedef uint64_t lc_len_t;
typedef struct lc_ctx_t lc_ctx_t;
typedef struct lc_socket_t lc_socket_t;
typedef struct lc_channel_t lc_channel_t;
typedef struct lc_msg_head_t lc_msg_head_t;

typedef struct lc_message_t {
	struct in6_addr dst;
	struct in6_addr src;
	uint64_t seq;
	uint64_t rnd;
	uint32_t sockid;
	char *msg;
	size_t len;
} lc_message_t;

/* create new librecast context and set up environment */
lc_ctx_t * lc_ctx_new();

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
int lc_getval(char *key, char *val);
int lc_setval(char *key, char *val);
int lc_channel_getval(lc_channel_t *chan, char *key, char *val);
int lc_channel_setval(lc_channel_t *chan, char *key, char *val);

/* destroy librecast context and clean up */
void lc_ctx_free(lc_ctx_t *ctx);

/* create librecast socket */
lc_socket_t *lc_socket_new(lc_ctx_t *ctx);

/* non-blocking socket listener, with callbacks */
int lc_socket_listen(lc_socket_t *sock, void (*callback_msg)(lc_message_t*),
			                void (*callback_err)(int));

/* stop listening on socket */
int lc_socket_listen_cancel(lc_socket_t *sock);

/* close socket */
void lc_socket_close(lc_socket_t *sock);

/* create a new channel handle */
lc_channel_t * lc_channel_new(lc_ctx_t *ctx, char * url);

/* bind channel to socket */
int lc_channel_bind(lc_socket_t *sock, lc_channel_t * channel);

/* find channel from address */
lc_channel_t * lc_channel_by_address(char addr[INET6_ADDRSTRLEN]);

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
ssize_t lc_msg_recv(lc_socket_t *sock, char **msg, struct in6_addr *dst, struct in6_addr *src);

/* send a message to a channel */
int lc_msg_send(lc_channel_t *channel, char *msg, size_t len);

/* Is librecast running?  */
int lc_librecast_running();

/* join multicast group by address
 * src can be NULL for ASM mode, or a valid source address for SSM */
int lc_joingroupbyaddr(unsigned char *addr, char *src);

/* join named multicast group
 * groupname is hashed and XORed with the base multicast address
 * src can be NULL for ASM mode, or a valid source address for SSM */
int lc_joingroupbyname(char*groupname, char *src);

/* get some random bytes */
int lc_getrandom(void *buf, size_t buflen, unsigned int flags);
