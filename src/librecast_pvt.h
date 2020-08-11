/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2017-2020 Brett Sheffield <bacs@librecast.net> */

#ifndef _LIBRECAST_PVT_H
#define _LIBRECAST_PVT_H 1

#include "../include/librecast/types.h"
#include "../include/librecast/db.h" /* FIXME */
#include <stddef.h>

typedef struct lc_ctx_t {
	lc_ctx_t *next;
	lc_ctx_db_t *db;
	uint32_t id;
	int fdtap;
	char *tapname;
	char *dbpath;
	lc_socket_t *sock_list;
	lc_channel_t *chan_list;
} lc_ctx_t;

typedef struct lc_socket_t {
	lc_socket_t *next;
	lc_ctx_t *ctx;
	pthread_t thread;
	uint32_t id;
	int socket;
} lc_socket_t;

typedef struct lc_channel_t {
	lc_channel_t *next;
	lc_ctx_t *ctx;
	struct lc_socket_t *socket;
	struct addrinfo *address;
	char *uri;
	uint32_t id;
	lc_seq_t seq; /* sequence number (Lamport clock) */
	lc_rnd_t rnd; /* random nonce */
} lc_channel_t;

typedef struct lc_message_head_t {
	uint64_t timestamp; /* nanosecond timestamp */
	lc_seq_t seq; /* sequence number */
	lc_rnd_t rnd; /* nonce */
	uint8_t op;
	lc_len_t len;
} __attribute__((__packed__)) lc_message_head_t;

typedef struct lc_query_param_t {
	lc_query_op_t op;
	void *data;
	lc_query_param_t *next;
} lc_query_param_t;

typedef struct lc_query_t {
	lc_ctx_t *ctx;
	lc_query_param_t *param;
} lc_query_t;

/* structure to pass to socket listening thread */
typedef struct lc_socket_call_t {
	lc_socket_t *sock;
	void (*callback_msg)(lc_message_t*);
	void (*callback_err)(int);
} lc_socket_call_t;

extern uint32_t ctx_id;
extern uint32_t sock_id;
extern uint32_t chan_id;

extern lc_ctx_t *ctx_list;
extern lc_socket_t *sock_list;
extern lc_channel_t *chan_list;

#define BUFSIZE 1500
#define DEFAULT_ADDR "ff3e::"
#define DEFAULT_PORT "4242"

#endif /* _LIBRECAST_PVT_H */
