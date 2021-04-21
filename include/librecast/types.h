/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2017-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _LIBRECAST_TYPES_H
#define _LIBRECAST_TYPES_H 1

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <librecast/errors.h>

#define LC_DEFAULT_PORT 4242
#define LC_BRIDGE_NAME "lc0"
#define LC_DATABASE_COUNT 32
#define DEFAULT_MULTICAST_LOOP 0
#define DEFAULT_MULTICAST_HOPS 255

typedef uint64_t lc_seq_t;
typedef uint64_t lc_rnd_t;
typedef uint64_t lc_len_t;
typedef struct lc_ctx_t lc_ctx_t;
typedef struct lc_socket_t lc_socket_t;
typedef struct lc_channel_t lc_channel_t;
typedef struct lc_msg_head_t lc_msg_head_t;
typedef struct lc_query_t lc_query_t;
typedef struct lc_query_param_t lc_query_param_t;
typedef void *lc_free_fn_t(void *msg, void *hint);

#define LC_OPCODES(X) \
	X(0x0, LC_OP_DATA, "DATA", lc_op_data) \
	X(0x1, LC_OP_PING, "PING", lc_op_ping) \
	X(0x2, LC_OP_PONG, "PONG", lc_op_pong) \
	X(0x3, LC_OP_GET,  "GET",  lc_op_get)  \
	X(0x4, LC_OP_SET,  "SET",  lc_op_set)  \
	X(0x5, LC_OP_DEL,  "DEL",  lc_op_del)  \
	X(0x6, LC_OP_RET,  "RET",  lc_op_ret)  \
	X(0x7, LC_OP_MAX,  "MAX",  lc_op_data)
#undef X

#define LC_OPCODE_ENUM(code, name, text, f) name = code,
#define LC_OPCODE_TEXT(code, name, text, f) case code: return text;
#define LC_OPCODE_FUN(code, name, text, f) case code: if (f) f(sc, msg); break;

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
	LC_QUERY_NOOP = 0,
	LC_QUERY_EQ = 1,
	LC_QUERY_NE = 2,
	LC_QUERY_LT = 4,
	LC_QUERY_GT = 8,
	LC_QUERY_TIME = 16,
	LC_QUERY_SRC = 32,
	LC_QUERY_DST = 64,
	LC_QUERY_CHANNEL = 128,
	LC_QUERY_DB = 256,
	LC_QUERY_KEY = 512,
	LC_QUERY_MIN = 1024,
	LC_QUERY_MAX = 2048,
} lc_query_op_t;

typedef enum {
	LC_ATTR_DATA,
	LC_ATTR_LEN,
	LC_ATTR_OPCODE,
} lc_msg_attr_t;

typedef struct lc_message_t {
	uint64_t timestamp;
	struct in6_addr dst;
	struct in6_addr src;
	lc_seq_t seq;
	lc_rnd_t rnd;
	lc_len_t len; /* byte length of message data */
	size_t bytes; /* outer byte size of packet */
	uint32_t sockid;
	lc_opcode_t op;
	lc_free_fn_t *free;
	lc_channel_t *chan;
	char srcaddr[INET6_ADDRSTRLEN];
	char dstaddr[INET6_ADDRSTRLEN];
	void *hint;
	void *data;
} lc_message_t;

typedef struct lc_messagelist_t {
	char *hash;
	uint64_t timestamp;
	void *data;
	struct lc_messagelist_t *next;
} lc_messagelist_t;

typedef struct {
	lc_len_t size;
	void    *data;
} lc_val_t;

/* structure to pass to socket listening thread */
typedef struct lc_socket_call_s {
	lc_socket_t *sock;
	void (*callback_msg)(lc_message_t*);
	void (*callback_err)(int);
} lc_socket_call_t;

extern void (*lc_op_handler[LC_OP_MAX])(lc_socket_call_t *, lc_message_t *);

#endif  /* _LIBRECAST_TYPES_H */
