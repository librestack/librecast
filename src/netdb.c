/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2017-2020 Brett Sheffield <bacs@librecast.net> */

#include "netdb.h"
#include "librecast_pvt.h"

#define _GNU_SOURCE
#include <librecast/net.h>
#include <librecast/netdb.h>
#include "log.h"
#include <stdlib.h>
#include <string.h>

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
	if (!pkt) return -1; /* ENOMEM - errno is set by malloc() */
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
