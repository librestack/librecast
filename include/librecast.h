/*
 * librecast.h - The librecast API
 * 
 */

#include <sys/types.h>

#define LIBRECASTD_NOT_RUNNING 0
#define LIBRECASTD_RUNNING 1

typedef struct lc_ctx_t lc_ctx_t;
typedef struct lc_socket_t lc_socket_t;
typedef struct lc_channel_t lc_channel_t;

/* create new librecast context and set up environment */
lc_ctx_t * lc_ctx_new();

/* destroy librecast context and clean up */
void lc_ctx_free(lc_ctx_t *ctx);

/* create librecast socket */
lc_socket_t *lc_socket_new(lc_ctx_t *ctx);

/* close socket */
void lc_socket_close(lc_socket_t *sock);

/* create a new channel handle */
lc_channel_t * lc_channel_new(lc_ctx_t *ctx, char * url);

/* bind channel to socket */
int lc_channel_bind(lc_socket_t *sock, lc_channel_t * channel);

/* unbind channel from socket */
int lc_channel_unbind(lc_channel_t * channel);

/* join librecast channel */
int lc_channel_join(lc_channel_t * channel);

/* leave a librecast channel */
int lc_channel_leave(lc_channel_t * channel);

/* free channel */
int lc_channel_free(lc_channel_t * channel);

/* blocking message receive */
ssize_t lc_msg_recv(lc_socket_t *sock, char **msg);

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

