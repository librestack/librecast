/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2017-2020 Brett Sheffield <bacs@librecast.net> */
/* librecast/db.h - direct access db functions
 * for network database functions see <librecast/netdb.h>
 */

#ifndef _LIBRECAST_DB_H
#define _LIBRECAST_DB_H 1

#include <librecast/types.h>
#include <lmdb.h>

typedef MDB_env lc_ctx_db_t;

/* open database */
int lc_db_open(lc_ctx_t *ctx, char *dbpath);

/* fetch a single key */
int lc_db_get(lc_ctx_t *ctx, const char *db, void *key, size_t klen, void **val, size_t *vlen);

/* set key/val in named database db */
int lc_db_set(lc_ctx_t *ctx, const char *db, void *key, size_t klen, void *val, size_t vlen);

/* delete key/val in named database db */
int lc_db_del(lc_ctx_t *ctx, const char *db, void *key, size_t klen, void *val, size_t vlen);

/* as lc_db_set(), respecting database modes  */
int lc_db_set_mode(lc_ctx_t *ctx, const char *db, void *key, size_t klen, void *val, size_t vlen, int mode);

/* set key/val index */
int lc_db_idx(lc_ctx_t *ctx, const char *left, const char *right, void *key, size_t klen, void *val, size_t vlen, int mode);

/* query functions */
int lc_query_new(lc_ctx_t *ctx, lc_query_t **q);
void lc_query_free(lc_query_t *q);
int lc_query_push(lc_query_t *q, lc_query_op_t op, void *data);
int lc_query_exec(lc_query_t *q, lc_messagelist_t **msg);
int lc_query_filter(MDB_txn *txn, MDB_val timestamp, MDB_val msgid, lc_query_t *q);

int lc_msg_filter(MDB_txn *txn, MDB_val msgid, char *database, char *filter);
int lc_msg_filter_time(MDB_val timestamp, lc_query_param_t *p);
void lc_msglist_free(lc_messagelist_t *msg);

/* store message in channel log */
int lc_channel_logmsg(lc_channel_t *chan, lc_message_t *msg);

#endif /* _LIBRECAST_DB_H */
