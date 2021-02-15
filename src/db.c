/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2017-2020 Brett Sheffield <bacs@librecast.net> */

#define _GNU_SOURCE
#include "db.h"
#include "librecast_pvt.h"
#include "log.h"
#include <librecast/net.h>
#include <inttypes.h>
#include <lmdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef MDB_env lc_ctx_db_t;

#define E(expr) if (err == 0) TEST((err = (expr)) == MDB_SUCCESS, #expr)
#define RET(expr) if (err == 0) TEST((err = (expr)) == MDB_SUCCESS, #expr); else return err
#define TEST(test, f) ((test) ? 0 : (logmsg(LOG_DEBUG, "ERROR(%i): %s: %s", err, #f, mdb_strerror(err)), err=LC_ERROR_DB_EXEC))

int lc_db_get(lc_ctx_t *ctx, const char *db, void *key, size_t klen, void **val, size_t *vlen)
{
	logmsg(LOG_TRACE, "%s", __func__);
	int err = 0;
	MDB_txn *txn;
	MDB_dbi dbi;
	MDB_val k, v;
	MDB_cursor *cursor;
	lc_ctx_db_t *env;

	if (ctx == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_CTX_REQUIRED);
	if (ctx->db == NULL)
		return lc_error_log(LOG_DEBUG, LC_ERROR_DB_REQUIRED);
	if (db == NULL)
		return lc_error_log(LOG_DEBUG, LC_ERROR_DB_REQUIRED);
	if (key == NULL || klen < 1)
		return lc_error_log(LOG_DEBUG, LC_ERROR_INVALID_PARAMS);
	logmsg(LOG_DEBUG, "%s() using dbpath='%s'", __func__, ctx->dbpath);
	env = ctx->db;
	k.mv_data = key;
	k.mv_size = klen;
	memset(&v, 0, sizeof(MDB_val));

	RET(mdb_txn_begin(env, NULL, 0, &txn));
	E(mdb_dbi_open(txn, db, MDB_CREATE, &dbi));
	if (err != 0)
		goto aborttxn;
	E(mdb_cursor_open(txn, dbi, &cursor));
	if (err != 0)
		goto aborttxn;
	if ((err = mdb_cursor_get(cursor, &k, &v, MDB_SET_KEY)) != 0) {
		if (err == MDB_NOTFOUND)
			err = LC_ERROR_DB_KEYNOTFOUND;
		else
			err = LC_ERROR_DB_EXEC;
	}
	else {
		*val = malloc(v.mv_size);
		if (*val == NULL) {
			err = LC_ERROR_MALLOC;
			goto aborttxn;
		}
		memcpy(*val, v.mv_data, v.mv_size);
		*vlen = v.mv_size;
	}
aborttxn:
	mdb_txn_abort(txn);

	return err;
}

int lc_db_set(lc_ctx_t *ctx, const char *db, void *key, size_t klen, void *val, size_t vlen)
{
	int err = 0;
	MDB_txn *txn;
	MDB_dbi dbi;
	MDB_val k, v;
	lc_ctx_db_t *env;

	if (ctx == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_CTX_REQUIRED);
	if (ctx->db == NULL)
		return lc_error_log(LOG_DEBUG, LC_ERROR_DB_REQUIRED);
	if (db == NULL)
		return lc_error_log(LOG_DEBUG, LC_ERROR_DB_REQUIRED);
	if (key == NULL || klen < 1)
		return lc_error_log(LOG_DEBUG, LC_ERROR_INVALID_PARAMS);
	logmsg(LOG_DEBUG, "%s() using dbpath='%s'", __func__, ctx->dbpath);
	env = ctx->db;
	k.mv_data = key;
	k.mv_size = klen;
	v.mv_data = val;
	v.mv_size = vlen;

	RET(mdb_txn_begin(env, NULL, 0, &txn));
	E(mdb_dbi_open(txn, db, MDB_CREATE, &dbi));
	if (err != 0)
		goto aborttxn;
	E(mdb_put(txn, dbi, &k, &v, 0));
	if (err != 0)
		goto aborttxn;
	RET(mdb_txn_commit(txn));

	return err;
aborttxn:
	mdb_txn_abort(txn);
	return err;
}

int lc_db_del(lc_ctx_t *ctx, const char *db, void *key, size_t klen, void *val, size_t vlen)
{
	int err = 0;
	MDB_txn *txn;
	MDB_dbi dbi;
	MDB_val k, v;
	lc_ctx_db_t *env;

	if (ctx == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_CTX_REQUIRED);
	if (ctx->db == NULL)
		return lc_error_log(LOG_DEBUG, LC_ERROR_DB_REQUIRED);
	if (db == NULL)
		return lc_error_log(LOG_DEBUG, LC_ERROR_DB_REQUIRED);
	if (key == NULL || klen < 1)
		return lc_error_log(LOG_DEBUG, LC_ERROR_INVALID_PARAMS);
	logmsg(LOG_DEBUG, "%s() using dbpath='%s'", __func__, ctx->dbpath);
	env = ctx->db;
	k.mv_data = key;
	k.mv_size = klen;
	v.mv_data = val;
	v.mv_size = vlen;

	RET(mdb_txn_begin(env, NULL, 0, &txn));
	E(mdb_dbi_open(txn, db, MDB_CREATE, &dbi));
	if (err != 0)
		goto aborttxn;
	E(mdb_del(txn, dbi, &k, &v));
	if (err != 0)
		goto aborttxn;
	RET(mdb_txn_commit(txn));

	return err;
aborttxn:
	mdb_txn_abort(txn);
	return err;
}

int lc_db_set_mode(lc_ctx_t *ctx, const char *db, void *key, size_t klen, void *val, size_t vlen, int mode)
{
	int err = 0;
	MDB_txn *txn;
	MDB_dbi dbi;
	MDB_val k, v;
	lc_ctx_db_t *env;
	int flags;

	if (ctx == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_CTX_REQUIRED);
	if (ctx->db == NULL)
		return lc_error_log(LOG_DEBUG, LC_ERROR_DB_REQUIRED);
	if (db == NULL)
		return lc_error_log(LOG_DEBUG, LC_ERROR_DB_REQUIRED);
	if (key == NULL || klen < 1)
		return lc_error_log(LOG_DEBUG, LC_ERROR_INVALID_PARAMS);

	env = ctx->db;

	flags = MDB_CREATE;
	if ((mode & LC_DB_MODE_DUP) == LC_DB_MODE_DUP)
		flags |= MDB_DUPSORT;
	if ((mode & LC_DB_MODE_INT) == LC_DB_MODE_INT && (mode & LC_DB_MODE_DUP) == LC_DB_MODE_DUP)
		flags |= MDB_INTEGERDUP;
	else if ((mode & LC_DB_MODE_INT) == LC_DB_MODE_INT)
		flags |= MDB_INTEGERKEY;

	k.mv_data = key;
	k.mv_size = klen;
	v.mv_data = val;
	v.mv_size = vlen;

	RET(mdb_txn_begin(env, NULL, 0, &txn));
	E(mdb_dbi_open(txn, db, flags, &dbi));
	if (err != 0)
		goto aborttxn;
	E(mdb_put(txn, dbi, &k, &v, 0));
	if (err != 0)
		goto aborttxn;
	RET(mdb_txn_commit(txn));

	return err;
aborttxn:
	mdb_txn_abort(txn);
	return err;
}

int lc_db_idx(lc_ctx_t *ctx, const char *left, const char *right, void *key, size_t klen, void *val, size_t vlen, int mode)
{
	int err = 0;
	char *db;

	if (ctx == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_CTX_REQUIRED);
	if (ctx->db == NULL)
		return lc_error_log(LOG_DEBUG, LC_ERROR_DB_REQUIRED);
	if (left == NULL)
		return lc_error_log(LOG_DEBUG, LC_ERROR_INVALID_PARAMS);
	if (key == NULL || klen < 1)
		return lc_error_log(LOG_DEBUG, LC_ERROR_INVALID_PARAMS);

	if ((mode & LC_DB_MODE_LEFT) == LC_DB_MODE_LEFT) {
		if (right == NULL)
			db = strdup(left);
		else
			asprintf(&db, "%s_%s", left, right);

		err = lc_db_set_mode(ctx, db, key, klen, val, vlen, mode);
		free(db);
	}

	if ((mode & LC_DB_MODE_RIGHT) == LC_DB_MODE_RIGHT) {
		if (right == NULL)
			db = strdup(left);
		else
			asprintf(&db, "%s_%s", right, left);

		err = lc_db_set_mode(ctx, db, val, vlen, key, klen, mode);
		free(db);
	}

	return err;
}

int lc_query_new(lc_ctx_t *ctx, lc_query_t **q)
{
	if (ctx == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_CTX_REQUIRED);
	if (ctx->db == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_DB_REQUIRED);

	if ((*q = calloc(1, sizeof(lc_query_t))) == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_MALLOC);

	(*q)->ctx = ctx;

	return 0;
}

void lc_query_free(lc_query_t *q)
{
	if (!q) return;
	lc_query_param_t *p, *tmp;
	for (p = q->param; p; free(tmp)) {
		tmp = p;
		p = p->next;
	}
	free(q);
}

int lc_query_push(lc_query_t *q, lc_query_op_t op, void *data)
{
	lc_query_param_t *new, *p;

	if (q == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_INVALID_PARAMS);

	if ((new = calloc(1, sizeof(lc_query_param_t))) == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_MALLOC);

	new->op = op;
	new->data = data;

	/* append new query to end of linked list */
	if (q->param == NULL)
		q->param = new;
	else {
		for(p = q->param; p->next != NULL; p = p->next);
		p->next = new;
	}

	return 0;
}

int lc_msg_filter(MDB_txn *txn, MDB_val msgid, char *database, char *filter)
{
	int rc = 0;
	int err = 0;
	MDB_dbi dbi;
	MDB_val data;
	MDB_cursor *cursor;

	if (filter == NULL)
		return 1;

	E(mdb_dbi_open(txn, database, MDB_DUPSORT, &dbi));
	if (err == 0) {
		if (mdb_cursor_open(txn, dbi, &cursor) == 0) {
			data.mv_data = filter;
			data.mv_size = strlen(filter);
			rc = mdb_cursor_get(cursor, &msgid, &data, MDB_GET_BOTH);
		}
		mdb_cursor_close(cursor);
	}

	return (rc == 0 && err == 0) ? 1 : 0;
}

int lc_msg_filter_time(MDB_val timestamp, lc_query_param_t *p)
{
	uint64_t t = *(uint64_t *)(p->data);
	uint64_t v = strtoumax(timestamp.mv_data, NULL, 10);

	if ((p->op & LC_QUERY_EQ) == LC_QUERY_EQ) {
		if (v == t) return 1;
	}
	else if ((p->op & LC_QUERY_LT) == LC_QUERY_LT) {
		if (v < t) return 1;
	}
	else if ((p->op & LC_QUERY_GT) == LC_QUERY_GT) {
		if (v > t) return 1;
	}
	return 0;
}

int lc_query_filter(MDB_txn *txn, MDB_val timestamp, MDB_val msgid, lc_query_t *q)
{
	lc_query_param_t *p;
	for (p = q->param; p != NULL; p = p->next) {
		if ((p->op & LC_QUERY_CHANNEL) == LC_QUERY_CHANNEL) {
			if (!(lc_msg_filter(txn, msgid, "message_channel", p->data)))
				return 0;
			continue;
		}
		if ((p->op & LC_QUERY_TIME) == LC_QUERY_TIME) {
			if (!(lc_msg_filter_time(timestamp, p)))
				return 0;
			continue;
		}
		if ((p->op & LC_QUERY_DB) == LC_QUERY_DB) {
			char *db = p->data;
			p = p->next;
			if (!(lc_msg_filter(txn, msgid, db, p->data)))
				return 0;
			continue;
		}
	}
	return 1;
}

int lc_query_exec(lc_query_t *q, lc_messagelist_t **msglist)
{
	int err = 0;
	int msgs = 0;
	int rc;
	MDB_txn *txn = NULL;
	MDB_dbi dbi_msg, dbi_idx_t;
	MDB_cursor *cursor = NULL;
	MDB_val key, data, data_msg;
	MDB_cursor_op op;
	char *kval = "";
	lc_messagelist_t *msg, *lastmsg = NULL;

	if (!q) {
		lc_error_log(LOG_ERROR, LC_ERROR_QUERY_REQUIRED);
		return -1;
	}
	if (q->ctx->db == NULL) return -1;
	E(mdb_txn_begin(q->ctx->db, NULL, MDB_RDONLY, &txn));
	E(mdb_dbi_open(txn, "timestamp_message", MDB_INTEGERDUP, &dbi_idx_t));
	E(mdb_dbi_open(txn, "message", MDB_DUPSORT, &dbi_msg));
	E(mdb_cursor_open(txn, dbi_idx_t, &cursor));
	if (err != 0)
		goto cleanup;

	key.mv_data = &kval;
	key.mv_size = strlen(key.mv_data);

	/* fetch messages in timestamp order */
	for (op = MDB_FIRST; (rc = mdb_cursor_get(cursor, &key, &data, op)) == 0; op = MDB_NEXT) {
		/* filter msgs */
		if (!(lc_query_filter(txn, key, data, q)))
			continue;

		/* retreive message data by id */
		rc = mdb_get(txn, dbi_msg, &data, &data_msg);
		if (rc != 0) {
			logmsg(LOG_DEBUG, "%s", mdb_strerror(rc));
			continue;
		}

		/* copy message */
		msg = calloc(1, sizeof(lc_messagelist_t));
		if (msg == NULL) {
			logmsg(LOG_DEBUG, "%s", strerror(errno));
			break;
		}
		msg->hash = malloc(data.mv_size);
		if (msg->hash == NULL) {
			logmsg(LOG_DEBUG, "%s", strerror(errno));
			free(msg);
			break;
		}
		memcpy(msg->hash, data.mv_data, data.mv_size);
		msg->timestamp = strtoumax(key.mv_data, NULL, 10);
		msg->data = strndup(data_msg.mv_data, data_msg.mv_size);
		if (msg->data == NULL) {
			logmsg(LOG_DEBUG, "%s", strerror(errno));
			free(msg->hash);
			free(msg);
			break;
		}

		/* append message to result list */
		if (*msglist == NULL)
			*msglist = msg;
		else if (lastmsg)
			lastmsg->next = msg;
		lastmsg = msg;
		msgs++;
	}

cleanup:
	mdb_cursor_close(cursor);
	mdb_txn_abort(txn);

	return msgs;
}

void lc_msglist_free(lc_messagelist_t *msg)
{
	lc_messagelist_t *tmp;

	while (msg != NULL) {
		free(msg->hash);
		free(msg->data);
		tmp = msg;
		msg = msg->next;
		free(tmp);
	}
	free(msg);
	msg = NULL;
}

int lc_db_open(lc_ctx_t *ctx, char *dbpath)
{
	/* prepare databases */
	int err = 0;
	if (dbpath == NULL) return LC_ERROR_DB_REQUIRED;
	ctx->dbpath = dbpath;
	E(mdb_env_create(&ctx->db));
	E(mdb_env_set_maxdbs(ctx->db, LC_DATABASE_COUNT));
	E(mdb_env_open(ctx->db, ctx->dbpath, 0, 0600));
	if (err != 0) {
		mdb_env_close(ctx->db);
		ctx->db = NULL;
		return LC_ERROR_DB_OPEN;
	}
	return 0;
}

int lc_channel_logmsg(lc_channel_t *chan, lc_message_t *msg)
{
	logmsg(LOG_TRACE, "%s", __func__);
	lc_ctx_db_t *db;
	lc_ctx_t *ctx;
	int err = 0;
	int mode;
	char *val;
	size_t klen = SHA_DIGEST_LENGTH;
	size_t vlen = 0;
	unsigned char key[SHA_DIGEST_LENGTH];

	if (!chan) return lc_error_log(LOG_ERROR, LC_ERROR_CHANNEL_REQUIRED);
	if (!msg) return lc_error_log(LOG_ERROR, LC_ERROR_MESSAGE_REQUIRED);

	/* only log data messages */
	if (msg->op != LC_OP_DATA)
		return 0;

	ctx = chan->ctx;
	if ((db = ctx->db) == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_DB_REQUIRED);

	if ((err = lc_msg_id(msg, (unsigned char *)key)) != 0)
		return err;

	/* log message to database */
	E(lc_db_set(ctx, "message", key, klen, msg->data, msg->len));

	/* metadata indexes */
	mode = LC_DB_MODE_DUP | LC_DB_MODE_BOTH;
	E(lc_db_idx(ctx, "message", "channel", key, klen, chan->uri, strlen(chan->uri), mode));
	E(lc_db_idx(ctx, "message", "src", key, klen, msg->srcaddr, INET6_ADDRSTRLEN, mode));
	E(lc_db_idx(ctx, "message", "dst", key, klen, msg->dstaddr, INET6_ADDRSTRLEN, mode));
	vlen = asprintf(&val, "%"PRIu64"", msg->timestamp);
	mode = LC_DB_MODE_DUP | LC_DB_MODE_LEFT ;
	E(lc_db_idx(ctx, "message", "timestamp", key, klen, val, vlen, mode));
	mode = LC_DB_MODE_DUP | LC_DB_MODE_RIGHT | LC_DB_MODE_INT;
	E(lc_db_idx(ctx, "message", "timestamp", key, klen, val, vlen, mode));
	free(val);

	logmsg(LOG_FULLTRACE, "%s exiting", __func__);
	return err;
}
