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
#define LC_DATABASE_DIR "/var/cache/librecast"
#define LC_DATABASE_COUNT 32

typedef uint64_t lc_seq_t;
typedef uint64_t lc_rnd_t;
typedef uint64_t lc_len_t;
typedef struct lc_ctx_t lc_ctx_t;
typedef struct lc_socket_t lc_socket_t;
typedef struct lc_channel_t lc_channel_t;
typedef struct lc_msg_head_t lc_msg_head_t;
typedef void *lc_free_fn_t(void *msg, void *hint);

#define LC_OPCODES(X) \
	X(0x0, LC_OP_DATA, "DATA", lc_op_data) \
	X(0x1, LC_OP_PING, "PING", lc_op_ping) \
	X(0x2, LC_OP_PONG, "PONG", lc_op_pong) \
	X(0x3, LC_OP_GET,  "GET",  lc_op_get) \
	X(0x4, LC_OP_SET,  "SET",  lc_op_set) \
	X(0x5, LC_OP_DEL,  "DEL",  lc_op_del) \
	X(0x6, LC_OP_RET,  "RET",  lc_op_ret)
#undef X

#define LC_OPCODE_ENUM(code, name, text, f) name = code,
#define LC_OPCODE_TEXT(code, name, text, f) case code: return text;
#define LC_OPCODE_FUN(code, name, text, f) case code: f(sc, &msg); break;

typedef enum {
	LC_OPCODES(LC_OPCODE_ENUM)
} lc_opcode_t;

typedef enum {
	LC_DB_MODE_DUP = 1,
	LC_DB_MODE_LEFT = 2,
	LC_DB_MODE_RIGHT = 4,
	LC_DB_MODE_BOTH = 6,
	LC_DB_MODE_INT = 8,
} lc_db_mode_t;

typedef enum {
	LC_ATTR_DATA,
	LC_ATTR_LEN,
	LC_ATTR_OPCODE,
} lc_msg_attr_t;

typedef struct lc_message_t {
	struct in6_addr dst;
	struct in6_addr src;
	lc_seq_t seq;
	lc_rnd_t rnd;
	lc_len_t len;
	uint32_t sockid;
	lc_opcode_t op;
	lc_free_fn_t *free;
	lc_channel_t *chan;
	char *srcaddr;
	char *dstaddr;
	void *hint;
	void *data;
} lc_message_t;

typedef struct {
	lc_len_t size;
	void    *data;
} lc_val_t;

/* create new librecast context and set up environment */
lc_ctx_t * lc_ctx_new();

/* manage message structures */
int lc_msg_init(lc_message_t *msg);
int lc_msg_init_size(lc_message_t *msg, size_t len);
int lc_msg_init_data(lc_message_t *msg, void *data, size_t len, void *f, void *hint);
void lc_msg_free(void *msg);
int lc_msg_get(lc_message_t *msg, lc_msg_attr_t attr, void *value);
int lc_msg_set(lc_message_t *msg, lc_msg_attr_t attr, void *value);

/* return pointer to message payload */
void *lc_msg_data(lc_message_t *msg);

/* fetch a single key */
int lc_db_get(lc_ctx_t *ctx, const char *db, void *key, size_t klen, void **val, size_t *vlen);

/* set key/val in named database db */
int lc_db_set(lc_ctx_t *ctx, const char *db, void *key, size_t klen, void *val, size_t vlen);

/* as lc_db_set(), respecting database modes  */
int lc_db_set_mode(lc_ctx_t *ctx, const char *db, void *key, size_t klen, void *val, size_t vlen, int mode);

/* set key/val index */
int lc_db_idx(lc_ctx_t *ctx, const char *left, const char *right, void *key, size_t klen, void *val, size_t vlen, int mode);

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
int lc_channel_getval(lc_channel_t *chan, lc_val_t *key, lc_val_t *val);
int lc_channel_setval(lc_channel_t *chan, lc_val_t *key, lc_val_t *val);

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
int lc_msg_send(lc_channel_t *channel, lc_message_t *msg);

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
