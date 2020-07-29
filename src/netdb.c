/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2017-2020 Brett Sheffield <bacs@librecast.net> */

#include "netdb.h"
#include "librecast_pvt.h"

#define _GNU_SOURCE
#include <librecast/net.h>
#include "errors.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>

/* opcode handlers */
#if 0
void lc_op_data(lc_socket_call_t *sc, lc_message_t *msg);
void lc_op_ping(lc_socket_call_t *sc, lc_message_t *msg);
void lc_op_pong(lc_socket_call_t *sc, lc_message_t *msg);
void lc_op_get(lc_socket_call_t *sc, lc_message_t *msg);
void lc_op_set(lc_socket_call_t *sc, lc_message_t *msg);
void lc_op_del(lc_socket_call_t *sc, lc_message_t *msg);
#endif

int lc_channel_getval(lc_channel_t *chan, lc_val_t *key)
{
	logmsg(LOG_TRACE, "%s", __func__);
	lc_message_t msg;
	ssize_t err = 0;
	int i = LC_OP_GET;

	if (chan == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_CHANNEL_REQUIRED);
	if (key == NULL || key->size == 0 || key->data == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_INVALID_PARAMS);

	lc_msg_init_size(&msg, key->size);
	lc_msg_set(&msg, LC_ATTR_OPCODE, &i);
	memcpy(lc_msg_data(&msg), key->data, key->size);
	err = lc_msg_send(chan, &msg);
	lc_msg_free(&msg);

	return (err < 0) ? LC_ERROR_NET_SEND : 0;
}

int lc_channel_setval(lc_channel_t *chan, lc_val_t *key, lc_val_t *val)
{
	logmsg(LOG_TRACE, "%s", __func__);
	lc_message_t msg;
	lc_len_t keylen;
	void *pkt;
	ssize_t err = 0;

	if (chan == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_CHANNEL_REQUIRED);
	if (key == NULL || key->size == 0 || key->data == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_INVALID_PARAMS);
	if (val == NULL || val->size == 0 || val->data == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_INVALID_PARAMS);

	/* pack data: [keylen][key][data] */
	keylen = htobe64(key->size);
	pkt = malloc(sizeof(lc_len_t) + key->size + val->size);
	memcpy(pkt, &keylen, sizeof(lc_len_t));
	memcpy(pkt + sizeof(lc_len_t), key->data, key->size);
	memcpy(pkt + sizeof(lc_len_t) + key->size, val->data, val->size);

	/* prepare message */
	lc_msg_init_data(&msg, pkt, sizeof(lc_len_t) + key->size + val->size, NULL, NULL);
	int i = LC_OP_SET;
	lc_msg_set(&msg, LC_ATTR_OPCODE, &i);

	/* send */
	err = lc_msg_send(chan, &msg);
	lc_msg_free(&msg);
	free(pkt);

	return (err < 0) ? LC_ERROR_NET_SEND : 0;
}
#if 0
char *lc_opcode_text(lc_opcode_t op)
{
	switch (op) {
		LC_OPCODES(LC_OPCODE_TEXT)
	}
	return NULL;
}

void lc_op_data(lc_socket_call_t *sc, lc_message_t *msg)
{
	logmsg(LOG_TRACE, "%s", __func__);

	/* callback to message handler */
	if (sc->callback_msg)
		sc->callback_msg(msg);
}

void lc_op_ping(lc_socket_call_t *sc, lc_message_t *msg)
{
	logmsg(LOG_TRACE, "%s", __func__);
	int opt;

	/* received PING, echo PONG back to same channel */
	opt = LC_OP_PONG;
	lc_msg_set(msg, LC_ATTR_OPCODE, &opt);
	lc_msg_send(msg->chan, msg);

	/* TODO: send PONG reply to global scope solicited-node multicast address of src */

	/* TODO: ff0e:: + low-order 24 bits of src address */

}

void lc_op_pong(lc_socket_call_t *sc, lc_message_t *msg)
{
	logmsg(LOG_TRACE, "%s", __func__);

	/* callback to message handler */
	if (sc->callback_msg)
		sc->callback_msg(msg);
}

void lc_op_get(lc_socket_call_t *sc, lc_message_t *msg)
{
	logmsg(LOG_TRACE, "%s", __func__);

	lc_channel_t *chan;
	lc_ctx_db_t *db;
	size_t vlen;
	lc_opcode_t opcode = LC_OP_RET;
	int err = 0;
	char *key;
	char *val = NULL;
	char *pkt;

	if (msg == NULL) {
		lc_error_log(LOG_ERROR, LC_ERROR_MESSAGE_REQUIRED);
		return;
	}
	if (msg->data == NULL) {
		lc_error_log(LOG_ERROR, LC_ERROR_MESSAGE_EMPTY);
		return;
	}
	chan = msg->chan;
	if (chan == NULL) {
		lc_error_log(LOG_ERROR, LC_ERROR_CHANNEL_REQUIRED);
		return;
	}
	db = chan->ctx->db;
	if (db == NULL) {
		lc_error_log(LOG_ERROR, LC_ERROR_DB_REQUIRED);
		return;
	}

	/* read requested value from database */
	key = malloc(msg->len + 1);
	memcpy(key, msg->data, msg->len);
	key[msg->len] = '\0';
	if ((err = lc_db_get(chan->ctx, chan->uri, key, msg->len, (void *)&val, &vlen)) != 0) {
		lc_error_log(LOG_DEBUG, err);
		goto errexit;
	}

	/* send response with data (opcode: RET) */
	/* [seq][rnd][data] */
	pkt = malloc(vlen + sizeof(lc_seq_t) + sizeof(lc_rnd_t));
	memcpy(pkt, &msg->seq, sizeof(lc_seq_t));
	memcpy(pkt + sizeof(lc_seq_t), &msg->rnd, sizeof(lc_rnd_t));
	memcpy(pkt + sizeof(lc_seq_t) + sizeof(lc_rnd_t), val, vlen);
	lc_msg_init_data(msg, pkt, vlen + sizeof(lc_seq_t) + sizeof(lc_rnd_t), NULL, NULL);
	lc_msg_set(msg, LC_ATTR_OPCODE, &opcode);
	lc_msg_send(chan, msg);

	/* DEBUG logging */
	char *strkey, *strval;
	strkey = strndup(key, msg->len);
	strval = strndup(val, vlen);
	logmsg(LOG_DEBUG, "getting key '%s' on channel '%s' == '%s'", strkey, chan->uri, strval);
	free(strkey);
	free(strval);

	free(val);
errexit:
	free(key);
	logmsg(LOG_FULLTRACE, "%s exiting", __func__);
}

void lc_op_ret(lc_socket_call_t *sc, lc_message_t *msg)
{
	logmsg(LOG_TRACE, "%s", __func__);

	/* callback to message handler */
	if (sc->callback_msg)
		sc->callback_msg(msg);
}

void lc_op_set(lc_socket_call_t *sc, lc_message_t *msg)
{
	logmsg(LOG_TRACE, "%s", __func__);

	lc_ctx_db_t *db;
	lc_len_t klen;
	lc_len_t vlen;
	char *key;
	char *val;
	lc_channel_t *chan;

	if (msg == NULL) {
		lc_error_log(LOG_ERROR, LC_ERROR_MESSAGE_REQUIRED);
		return;
	}
	if (msg->data == NULL) {
		lc_error_log(LOG_ERROR, LC_ERROR_MESSAGE_EMPTY);
		return;
	}
	chan = msg->chan;
	if (chan == NULL) {
		lc_error_log(LOG_ERROR, LC_ERROR_CHANNEL_REQUIRED);
		return;
	}
	db = chan->ctx->db;
	if (db == NULL) {
		lc_error_log(LOG_ERROR, LC_ERROR_DB_REQUIRED);
		return;
	}

	/* extract key and data */
	memcpy(&klen, msg->data, sizeof(lc_len_t));
	klen = be64toh(klen);
	vlen = msg->len - klen - sizeof(lc_len_t);
	key = malloc(klen);
	val = malloc(vlen);
	memcpy(key, msg->data + sizeof(lc_len_t), klen);
	memcpy(val, msg->data + sizeof(lc_len_t) + klen, vlen);

	/* DEBUG logging */
	char *strkey, *strval;
	strkey = strndup(key, klen);
	strval = strndup(val, vlen);
	logmsg(LOG_DEBUG, "setting key '%s' on channel '%s' to '%s'", strkey, chan->uri, strval);
	free(strkey);
	free(strval);

	/* write to database */
	lc_db_set(chan->ctx, chan->uri, key, klen, val, vlen);

	free(key);
	free(val);

	/* callback to message handler */
	if (sc->callback_msg)
		sc->callback_msg(msg);

	logmsg(LOG_FULLTRACE, "%s exiting", __func__);
}

void lc_op_del(lc_socket_call_t *sc, lc_message_t *msg)
{
	logmsg(LOG_TRACE, "%s", __func__);

	/* TODO */
}
#endif
