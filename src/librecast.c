/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2017-2020 Brett Sheffield <bacs@librecast.net> */

#define _GNU_SOURCE
#include "librecast_pvt.h"
#include <librecast/net.h>
#include <libbridge.h>
#include "errors.h"
#include "log.h"
#include <assert.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef _LIBBRIDGE_H
#include <net/if.h>
#endif

uint32_t ctx_id = 0;
uint32_t sock_id = 0;
uint32_t chan_id = 0;

lc_ctx_t *ctx_list = NULL;
lc_socket_t *sock_list = NULL;
lc_channel_t *chan_list = NULL;

#define BUFSIZE 1500
#define DEFAULT_ADDR "ff3e::"
#define DEFAULT_PORT "4242"

/* socket listener thread */
void *lc_socket_listen_thread(void *sc);

/* opcode handlers */
void lc_op_data(lc_socket_call_t *sc, lc_message_t *msg);
void lc_op_ping(lc_socket_call_t *sc, lc_message_t *msg);
void lc_op_pong(lc_socket_call_t *sc, lc_message_t *msg);
void lc_op_get(lc_socket_call_t *sc, lc_message_t *msg);
void lc_op_set(lc_socket_call_t *sc, lc_message_t *msg);
void lc_op_ret(lc_socket_call_t *sc, lc_message_t *msg);
void lc_op_del(lc_socket_call_t *sc, lc_message_t *msg);

int lc_bridge_init(void)
{
	if (br_init()) {
		lc_error_log(LOG_ERROR, LC_ERROR_BRIDGE_INIT);
		return -1;
	}
	return 0;
}

int lc_bridge_new(char *brname)
{
	int err;

	switch (err = br_add_bridge(brname)) {
	case 0:
		break;
	case EEXIST:
		return lc_error_log(LOG_DEBUG, LC_ERROR_BRIDGE_EXISTS);
	default:
		logmsg(LOG_ERROR, "%s", strerror(err));
		return lc_error_log(LOG_ERROR, LC_ERROR_BRIDGE_ADD_FAIL);
	}
	logmsg(LOG_DEBUG, "(librecast) bridge %s created", brname);

	/* bring up bridge */
	logmsg(LOG_DEBUG, "(librecast) bringing up bridge %s", brname);
	if ((err = lc_link_set(brname, IFF_UP)) != 0) {
		return lc_error_log(LOG_ERROR, err);
	}

	return 0;
}

int lc_bridge_add_interface(const char *brname, const char *ifname) {
	int err;

	logmsg(LOG_DEBUG, "bridging %s to %s", ifname, brname);
	err = br_add_interface(brname, ifname);
	switch(err) {
	case 0:
		return 0;
	case ENODEV:
		if (if_nametoindex(ifname) == 0)
			lc_error_log(LOG_ERROR, LC_ERROR_IF_NODEV);
		else
			lc_error_log(LOG_ERROR, LC_ERROR_BRIDGE_NODEV);
		break;
	case EBUSY:
		lc_error_log(LOG_ERROR, LC_ERROR_IF_BUSY);
		break;
	case ELOOP:
		lc_error_log(LOG_ERROR, LC_ERROR_IF_LOOP);
		break;
	case EOPNOTSUPP:
		lc_error_log(LOG_ERROR, LC_ERROR_IF_OPNOTSUPP);
		break;
	default:
		lc_error_log(LOG_ERROR, LC_ERROR_IF_BRIDGE_FAIL);
	}

	return -1;
}

int lc_link_set(char *ifname, int flags)
{
	struct ifreq ifr;
	size_t len = strlen(ifname);
	int fd, err = 0;

	if (len >= IFNAMSIZ) return lc_error_log(LOG_ERROR, LC_ERROR_INVALID_PARAMS);
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		err = errno;
		logmsg(LOG_ERROR, "failed to create ioctl socket: %s", strerror(err));
		return LC_ERROR_SOCK_IOCTL;
	}
	memset(&ifr, 0, sizeof(ifr));
	memcpy(ifr.ifr_name, ifname, len);
	logmsg(LOG_DEBUG, "fetching flags for interface %s", ifr.ifr_name);
	if ((err = ioctl(fd, SIOCGIFFLAGS, &ifr)) == -1) {
	}
	logmsg(LOG_DEBUG, "setting flags for interface %s", ifr.ifr_name);
	ifr.ifr_flags |= flags;
	if ((err = ioctl(fd, SIOCSIFFLAGS, &ifr)) == -1) {
		err = errno;
		logmsg(LOG_ERROR, "ioctl failed: %s", strerror(err));
		err = LC_ERROR_IF_UP_FAIL;
	}
	close(fd);

	return err;
}

int lc_tap_create(char **ifname)
{
	struct ifreq ifr;
	int fd, err;

	/* create tap interface */
	if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
		err = errno;
		logmsg(LOG_ERROR, "open tun failed: %s", strerror(err));
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if (ioctl(fd, TUNSETIFF, (void *) &ifr) == -1) {
		err = errno;
		logmsg(LOG_ERROR, "ioctl (TUNSETIFF) failed: %s", strerror(err));
		close(fd);
		return -1;
	}
	logmsg(LOG_DEBUG, "created tap interface %s", ifr.ifr_name);
	*ifname = strdup(ifr.ifr_name);

	/* bring interface up */
	logmsg(LOG_DEBUG, "(librecast) bringing up interface %s", ifr.ifr_name);
	if ((err = lc_link_set(ifr.ifr_name, IFF_UP)) != 0) {
		close(fd);
		free(*ifname);
		lc_error_log(LOG_ERROR, err);
		return -1;
	}

	return fd;
}

void *lc_msg_init(lc_message_t *msg)
{
	return memset(msg, 0, sizeof(lc_message_t));
}

int lc_msg_init_size(lc_message_t *msg, size_t len)
{
	lc_msg_init(msg);
	if ((msg->data = malloc(len)) == NULL) {
		errno = ENOMEM;
		return -1;
	}
	msg->len = len;
	msg->free = (void *)free;
	return 0;
}

int lc_msg_init_data(lc_message_t *msg, void *data, size_t len, void *f, void *hint)
{
	lc_msg_init(msg);
	msg->len = len;
	msg->data = data;
	msg->free = f;
	msg->hint = hint;
	return 0;
}

void lc_msg_free(void *ptr)
{
	lc_message_t *msg = (lc_message_t *)ptr;
	if (*msg->free) {
		msg->free(msg->data, msg->hint);
		msg->data = NULL;
	}
}

void *lc_msg_data(lc_message_t *msg)
{
	return (!msg) ? NULL : msg->data;
}

int lc_msg_get(lc_message_t *msg, lc_msg_attr_t attr, void *value)
{
	if (msg == NULL)
		return LC_ERROR_INVALID_PARAMS;

	switch (attr) {
	case LC_ATTR_DATA:
		value = msg->data;
		break;
	case LC_ATTR_LEN:
		value = &msg->len;
		break;
	case LC_ATTR_OPCODE:
		value = &msg->op;
		break;
	default:
		return LC_ERROR_MSG_ATTR_UNKNOWN;
	}

	return 0;
}

int lc_msg_set(lc_message_t *msg, lc_msg_attr_t attr, void *value)
{
	if (msg == NULL)
		return LC_ERROR_INVALID_PARAMS;

	switch (attr) {
	case LC_ATTR_DATA:
		msg->data = value;
		break;
	case LC_ATTR_LEN:
		msg->len = *(lc_len_t *)value;
		break;
	case LC_ATTR_OPCODE:
		msg->op = *(lc_opcode_t *)value;
		break;
	default:
		return LC_ERROR_MSG_ATTR_UNKNOWN;
	}

	return 0;
}

int lc_msg_id(lc_message_t *msg, unsigned char id[SHA_DIGEST_LENGTH])
{
	int err = 0;

	/* create hash from msg + src + timestamp */
	SHA_CTX *c = NULL;
	c = malloc(sizeof(SHA_CTX));
	if (!SHA1_Init(c)) {
		err = lc_error_log(LOG_ERROR, LC_ERROR_HASH_INIT);
	}
	else if (!SHA1_Update(c, msg->data, msg->len)) {
		err = lc_error_log(LOG_ERROR, LC_ERROR_HASH_UPDATE);
	}
	else if (!SHA1_Update(c, msg->srcaddr, sizeof(struct in6_addr))) {
		err = lc_error_log(LOG_ERROR, LC_ERROR_HASH_UPDATE);
	}
	/* TODO: timestamp */
	else if (!SHA1_Final(id, c)) {
		err = lc_error_log(LOG_ERROR, LC_ERROR_HASH_FINAL);
	}
	free(c);

	return err;
}

int lc_hashgroup(char *baseaddr, char *groupname, char *hashaddr, unsigned int flags)
{
	logmsg(LOG_TRACE, "%s", __func__);
	int i;
	unsigned char hashgrp[SHA_DIGEST_LENGTH];
	unsigned char binaddr[16];
	SHA_CTX *c = NULL;

	if (groupname) {
		c = malloc(sizeof(SHA_CTX));
		if (!SHA1_Init(c))
			return lc_error_log(LOG_ERROR, LC_ERROR_HASH_INIT);
		if (!SHA1_Update(c, (unsigned char *)groupname, strlen(groupname)))
			return lc_error_log(LOG_ERROR, LC_ERROR_HASH_UPDATE);
		if (!SHA1_Update(c, &flags, sizeof(flags)))
			return lc_error_log(LOG_ERROR, LC_ERROR_HASH_UPDATE);
		if (!SHA1_Final(hashgrp, c))
			return lc_error_log(LOG_ERROR, LC_ERROR_HASH_FINAL);
		free(c);

		if (inet_pton(AF_INET6, baseaddr, &binaddr) != 1)
			return lc_error_log(LOG_ERROR, LC_ERROR_INVALID_BASEADDR);

		/* we have 112 bits (14 bytes) available for the group address
		 * XOR the hashed group with the base multicast address */
		for (i = 0; i < 14; i++) {
			binaddr[i+2] ^= hashgrp[i];
		}

		if (inet_ntop(AF_INET6, binaddr, hashaddr, INET6_ADDRSTRLEN) == NULL) {
			i = errno;
			logmsg(LOG_ERROR, "%s (inet_ntop) %s", __func__, strerror(i));
			return LC_ERROR_FAILURE;
		}
	}
	logmsg(LOG_FULLTRACE, "%s exiting", __func__);

	return 0;
}

lc_ctx_t * lc_ctx_new(void)
{
	logmsg(LOG_TRACE, "%s", __func__);
	lc_ctx_t *ctx, *p;

	lc_getrandom(&ctx_id, sizeof(ctx_id), 0);
	lc_getrandom(&sock_id, sizeof(sock_id), 0);
	lc_getrandom(&chan_id, sizeof(chan_id), 0);

	/* create bridge */
	if ((lc_bridge_init()) != 0)
		return NULL;
	lc_bridge_new(LC_BRIDGE_NAME);

	ctx = calloc(1, sizeof(lc_ctx_t));
	ctx->id = ++ctx_id;
	for (p = ctx_list; p != NULL; p = p->next) {
		if (p->next == NULL)
			p->next = ctx;
	}

	/* create TAP interface */
	char *tap = NULL;
	int fdtap;
	if ((fdtap = lc_tap_create(&tap)) == -1) {
		lc_error_log(LOG_ERROR, LC_ERROR_TAP_ADD_FAIL);
		logmsg(LOG_DEBUG, "continuing without tap/bridge");
	}
	else {
		logmsg(LOG_DEBUG, "bridging interface %s to bridge %s", tap, LC_BRIDGE_NAME);
		/* plug TAP into bridge */
		if ((lc_bridge_add_interface(LC_BRIDGE_NAME, tap)) == -1) {
			lc_error_log(LOG_ERROR, LC_ERROR_IF_BRIDGE_FAIL);
			goto ctx_err;
		}

		ctx->tapname = tap;
		ctx->fdtap = fdtap;
	}

	return ctx;
ctx_err:
	lc_ctx_free(ctx);
	return NULL;
}

uint32_t lc_ctx_get_id(lc_ctx_t *ctx)
{
	logmsg(LOG_TRACE, "%s", __func__);

	if (ctx == NULL) {
		lc_error_log(LOG_ERROR, LC_ERROR_CTX_REQUIRED);
		return 0;
	}

	return ctx->id;
}

uint32_t lc_socket_get_id(lc_socket_t *sock)
{
	logmsg(LOG_TRACE, "%s", __func__);
	if (sock == NULL) {
		lc_error_log(LOG_ERROR, LC_ERROR_SOCKET_REQUIRED);
		return 0;
	}
	return sock->id;
}

uint32_t lc_channel_get_id(lc_channel_t *chan)
{
	logmsg(LOG_TRACE, "%s", __func__);
	if (chan == NULL) {
		lc_error_log(LOG_ERROR, LC_ERROR_CHANNEL_REQUIRED);
		return 0;
	}
	return chan->id;
}

void lc_ctx_free(lc_ctx_t *ctx)
{
	logmsg(LOG_TRACE, "%s", __func__);
	if (ctx) {
		if (ctx->tapname)
			free(ctx->tapname);
		close(ctx->fdtap);
		if (ctx->db)
			mdb_env_close(ctx->db);
		free(ctx);
	}
	ctx = NULL;
}

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
	if (lc_msg_send(msg->chan, msg) == -1)
		logmsg(LOG_ERROR, "lc_msg_send error: '%s'", strerror(errno));

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

lc_socket_t * lc_socket_new(lc_ctx_t *ctx)
{
	logmsg(LOG_TRACE, "%s", __func__);
	lc_socket_t *sock, *p;
	int s, i;

	sock = calloc(1, sizeof(lc_socket_t));
	if (!sock) return NULL;
	sock->ctx = ctx;
	sock->id = ++sock_id;
	for (p = sock_list; p != NULL; p = p->next) {
		if (p->next == NULL)
			p->next = sock;
	}
	s = socket(AF_INET6, SOCK_DGRAM, 0);
	int err = errno;
	if (s == -1) {
		logmsg(LOG_DEBUG, "socket ERROR: %s", strerror(err));
		goto socket_err;
	}
	sock->socket = s;
	logmsg(LOG_DEBUG, "socket %i created with id %u", sock->socket, sock->id);

	/* request ancilliary control data */
	i = 1;
	if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &i, sizeof(i)) == -1)
		goto setsockopt_err;
	i = DEFAULT_MULTICAST_LOOP;
	if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &i, sizeof(i)) == -1)
		goto setsockopt_err;
	i = DEFAULT_MULTICAST_HOPS;
	if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &i, sizeof(i)) == -1)
		goto setsockopt_err;
	return sock;
setsockopt_err:
	close(s);
socket_err:
	p->next = NULL;
	free(sock);
	return NULL;
}

int lc_socket_getopt(lc_socket_t *sock, int optname, void *optval, socklen_t *optlen)
{
	if (sock == NULL) return lc_error_log(LOG_DEBUG, LC_ERROR_SOCKET_REQUIRED);
	return getsockopt(sock->socket, IPPROTO_IPV6, optname, optval, optlen);
}

int lc_socket_setopt(lc_socket_t *sock, int optname, const void *optval, socklen_t optlen)
{
	if (sock == NULL) return lc_error_log(LOG_DEBUG, LC_ERROR_SOCKET_REQUIRED);
	return setsockopt(sock->socket, IPPROTO_IPV6, optname, optval, optlen);
}

int lc_socket_listen(lc_socket_t *sock, void (*callback_msg)(lc_message_t*),
					void (*callback_err)(int))
{
	logmsg(LOG_TRACE, "%s", __func__);
	pthread_attr_t attr = {};
	lc_socket_call_t *sc;

	if (sock == NULL)
		return lc_error_log(LOG_DEBUG, LC_ERROR_SOCKET_REQUIRED);
	if (sock->thread != 0)
		return lc_error_log(LOG_DEBUG, LC_ERROR_SOCKET_LISTENING);

	sc = calloc(1, sizeof(lc_socket_call_t));
	sc->sock = sock;
	sc->callback_msg = callback_msg;
	sc->callback_err = callback_err;

	pthread_attr_init(&attr);
	pthread_create(&(sock->thread), &attr, lc_socket_listen_thread, sc);
	pthread_attr_destroy(&attr);

	return 0;
}

int lc_socket_listen_cancel(lc_socket_t *sock)
{
	int err;
	logmsg(LOG_TRACE, "%s", __func__);
	if (sock->thread != 0) {
		if ((err = pthread_cancel(sock->thread)) != 0)
			return lc_error_log(LOG_ERROR, LC_ERROR_THREAD_CANCEL);
		if ((err = pthread_join(sock->thread, NULL)) != 0)
			return lc_error_log(LOG_ERROR, LC_ERROR_THREAD_JOIN);
		sock->thread = 0;
	}

	return 0;
}

static void process_msg(lc_socket_call_t *sc, lc_message_t *msg)
{
	lc_channel_t *chan;
	inet_ntop(AF_INET6, &msg->dst, msg->dstaddr, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &msg->src, msg->srcaddr, INET6_ADDRSTRLEN);
	logmsg(LOG_DEBUG, "message destination %s", msg->dstaddr);
	logmsg(LOG_DEBUG, "message source      %s", msg->srcaddr);
	logmsg(LOG_DEBUG, "got data %zi bytes", msg->len);
	msg->sockid = sc->sock->id;

	/* update channel stats */
	chan = lc_channel_by_address(msg->dstaddr);
	msg->chan = chan;
	if (chan) {
		chan->seq = (msg->seq > chan->seq) ? msg->seq + 1 : chan->seq + 1;
		chan->rnd = msg->rnd;
		logmsg(LOG_DEBUG, "channel clock set to %lu.%lu", chan->seq, chan->rnd);
		lc_channel_logmsg(chan, msg); /* store in channel log */
	}

	/* process opcode */
	logmsg(LOG_DEBUG, "OPCODE received: %i", msg->op);
	switch (msg->op) {
		LC_OPCODES(LC_OPCODE_FUN)
	default:
		lc_error_log(LOG_ERROR, LC_ERROR_INVALID_OPCODE);
	}
}

void *lc_socket_listen_thread(void *arg)
{
	logmsg(LOG_TRACE, "%s", __func__);
	ssize_t len;
	lc_message_t msg;
	lc_socket_call_t *sc = arg;
	lc_msg_init(&msg);
	pthread_cleanup_push(free, arg);
	pthread_cleanup_push(lc_msg_free, &msg);
	while(1) {
		len = lc_msg_recv(sc->sock, &msg);
		if (len > 0) {
			process_msg(sc, &msg);
		}
		if (len < 0) {
			lc_msg_free(&msg);
			if (sc->callback_err)
				sc->callback_err(len);
		}
		lc_msg_free(&msg);
	}
	/* not reached */
	pthread_cleanup_pop(0);
	pthread_cleanup_pop(0);
	free(sc);
	return NULL;
}

void lc_socket_close(lc_socket_t *sock)
{
	logmsg(LOG_TRACE, "%s", __func__);
	if (sock) {
		lc_socket_listen_cancel(sock);
		if (sock->socket)
			close(sock->socket);
	}
	free(sock);
}

lc_channel_t * lc_channel_init(lc_ctx_t *ctx, char * grpaddr, char * service)
{
	logmsg(LOG_TRACE, "%s", __func__);
	lc_channel_t *channel, *p;
	struct addrinfo *addr = NULL;
	struct addrinfo hints = {0};
	int err = 0;

	if (!ctx) {
		lc_error_log(LOG_ERROR, LC_ERROR_CTX_REQUIRED);
		return NULL;
	}

	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	if (getaddrinfo(grpaddr, service, &hints, &addr) != 0) {
		err = errno;
		logmsg(LOG_ERROR, "getaddrinfo() failed: %s", strerror(err));
		return NULL;
	}

	channel = calloc(1, sizeof(lc_channel_t));
	channel->uri = NULL;
	channel->ctx = ctx;
	channel->id = ++chan_id;
	channel->seq = 0;
	channel->rnd = 0;
	channel->address = addr;

	if (chan_list == NULL) {
		chan_list = channel;
	}
	else {
		for (p = chan_list; p != NULL; p = p->next) {
			if (p->next == NULL) {
				p->next = channel;
				break;
			}
		}
	}

	return channel;
}

lc_channel_t * lc_channel_new(lc_ctx_t *ctx, char * uri)
{
	logmsg(LOG_TRACE, "%s", __func__);
	lc_channel_t *channel;
	char hashaddr[INET6_ADDRSTRLEN];

	if (!ctx) {
		lc_error_log(LOG_ERROR, LC_ERROR_CTX_REQUIRED);
		return NULL;
	}

	/* TODO: process url, extract port and address */

	if ((lc_hashgroup(DEFAULT_ADDR, uri, hashaddr, 0)) != 0)
		return NULL;

	logmsg(LOG_DEBUG, "channel group address: %s", hashaddr);

	channel = lc_channel_init(ctx, hashaddr, DEFAULT_PORT);
	channel->uri = uri;

	return channel;
}

int lc_channel_bind(lc_socket_t *sock, lc_channel_t * channel)
{
	logmsg(LOG_TRACE, "%s", __func__);
	struct addrinfo *addr;
	int err, opt;

	if (!sock)
		return lc_error_log(LOG_ERROR, LC_ERROR_SOCKET_REQUIRED);
	if (!channel)
		return lc_error_log(LOG_ERROR, LC_ERROR_CHANNEL_REQUIRED);

	addr = channel->address;
	channel->socket = sock;

	opt = 1;
	if ((setsockopt(sock->socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) == -1) {
		err = errno;
		logmsg(LOG_ERROR, "failed to set SO_REUSEADDR: %s", strerror(err));
	}

	logmsg(LOG_DEBUG, "binding socket id %u to channel id %u", sock->id, channel->id);
	if (bind(sock->socket, addr->ai_addr, addr->ai_addrlen) != 0) {
		err = errno;
		logmsg(LOG_ERROR, "failed to bind socket: %s", strerror(err));
		return LC_ERROR_SOCKET_BIND;
	}
	logmsg(LOG_DEBUG, "Bound to socket %i", sock->socket);

	return 0;
}

lc_channel_t * lc_channel_by_address(char addr[INET6_ADDRSTRLEN])
{
	logmsg(LOG_TRACE, "%s", __func__);
	lc_channel_t *p;
	char dst[INET6_ADDRSTRLEN];

	for (p = chan_list; p != NULL; p = p->next) {
		if ((getnameinfo(p->address->ai_addr, p->address->ai_addrlen, dst,
				INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST)) != 0)
		{
			continue;
		}
		if (strcmp(addr, dst) == 0)
			break;
	}

	return p;
}

lc_ctx_t *lc_channel_ctx(lc_channel_t *chan)
{
	return chan->ctx;
}

char *lc_channel_uri(lc_channel_t *chan)
{
	return chan->uri;
}

int lc_channel_unbind(lc_channel_t * channel)
{
	logmsg(LOG_TRACE, "%s", __func__);
	channel->socket = NULL;
	return 0;
}

int lc_channel_join(lc_channel_t * channel)
{
	logmsg(LOG_TRACE, "%s", __func__);

	struct ipv6_mreq req;
	struct ifaddrs *ifaddr, *ifa;
	int sock;
	struct addrinfo *addr;
	int joins = 0;

	if (channel == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_CHANNEL_REQUIRED);
	if (channel->socket == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_SOCKET_REQUIRED);

	sock = channel->socket->socket;
	addr = channel->address;

	memcpy(&req.ipv6mr_multiaddr,
		&((struct sockaddr_in6*)(addr->ai_addr))->sin6_addr,
		sizeof(req.ipv6mr_multiaddr));

	if (getifaddrs(&ifaddr) == -1) {
		logmsg(LOG_DEBUG, "Failed to get interface list; using default");
		req.ipv6mr_interface = 0; /* default interface */
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &req, sizeof(req)) != 0)
			goto join_fail;
		logmsg(LOG_DEBUG, "Multicast join succeeded on default interface");
		return 0;
	}

	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family != AF_INET6) continue; /* only ipv6 */
		req.ipv6mr_interface = if_nametoindex(ifa->ifa_name);
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &req,
					sizeof(req)) == 0)
		{
			logmsg(LOG_DEBUG, "Multicast join succeeded on %s", ifa->ifa_name);
			joins++;
		}
	}
	freeifaddrs(ifaddr);
	if (joins > 0)
		return 0;

join_fail:
	logmsg(LOG_ERROR, "Multicast join failed");
	return LC_ERROR_MCAST_JOIN;
}

int lc_channel_part(lc_channel_t * channel)
{
	logmsg(LOG_TRACE, "%s", __func__);
	struct ipv6_mreq req;
	int sock = channel->socket->socket;
	struct addrinfo *addr = channel->address;

	memcpy(&req.ipv6mr_multiaddr,
		&((struct sockaddr_in6*)(addr->ai_addr))->sin6_addr,
		sizeof(req.ipv6mr_multiaddr));
	req.ipv6mr_interface = 0; /* default interface */
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,
		&req, sizeof(req)) != 0)
	{
		logmsg(LOG_ERROR, "Multicast leave failed");
		return LC_ERROR_MCAST_LEAVE;
	}

	return 0;
}

lc_socket_t *lc_channel_socket(lc_channel_t *channel)
{
	logmsg(LOG_TRACE, "%s", __func__);
	return channel->socket;
}

int lc_channel_socket_raw(lc_channel_t *channel)
{
	logmsg(LOG_TRACE, "%s", __func__);
	return channel->socket->socket;
}

int lc_socket_raw(lc_socket_t *sock)
{
	logmsg(LOG_TRACE, "%s", __func__);
	return sock->socket;
}

int lc_channel_free(lc_channel_t * channel)
{
	logmsg(LOG_TRACE, "%s", __func__);
	if (channel == NULL)
		return 0;
	if (channel->address != NULL)
		freeaddrinfo(channel->address);
	free(channel);
	return 0;
}

ssize_t lc_msg_recv(lc_socket_t *sock, lc_message_t *msg)
{
	logmsg(LOG_TRACE, "%s", __func__);
	int i = 0, err = 0;
	struct iovec iov[2];
	struct msghdr msgh;
	char buf[sizeof(lc_message_head_t)];
	char cmsgbuf[BUFSIZE];
	struct sockaddr_in6 from;
	socklen_t fromlen = sizeof(from);
	struct cmsghdr *cmsg;
	struct in6_pktinfo *pi;
	lc_message_head_t head;

	assert(sock != NULL);

	logmsg(LOG_DEBUG, "recvmsg on sock = %i", sock->socket);
	i = recv(sock->socket, NULL, 0, MSG_PEEK | MSG_TRUNC);
	logmsg(LOG_DEBUG, "%i bytes waiting to be read", i);

	if (i > sizeof(lc_message_head_t)) {
		err = lc_msg_init_size(msg, i - sizeof(lc_message_head_t));
		if (err) return lc_error_log(LOG_ERROR, LC_ERROR_MALLOC);
	}

	memset(&msgh, 0, sizeof(struct msghdr));
	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(lc_message_head_t);
	iov[1].iov_base = msg->data;
	iov[1].iov_len = msg->len;
	msgh.msg_control = cmsgbuf;
	msgh.msg_controllen = BUFSIZE;
	msgh.msg_name = &from;
	msgh.msg_namelen = fromlen;
	msgh.msg_iov = iov;
	msgh.msg_iovlen = 2;
	msgh.msg_flags = 0;

	i = recvmsg(sock->socket, &msgh, 0);
	err = errno;
	if (i == -1) {
		logmsg(LOG_DEBUG, "recvmsg ERROR: %s", strerror(err));
	}
	if (i > 0) {
	        /* read header */
		memcpy(&head, buf, sizeof(lc_message_head_t));
		msg->seq = be64toh(head.seq);
		msg->rnd = be64toh(head.rnd);
		msg->len = be64toh(head.len);
		msg->timestamp = be64toh(head.timestamp);
		msg->op = head.op;
		for (cmsg = CMSG_FIRSTHDR(&msgh);
		     cmsg != NULL;
		     cmsg = CMSG_NXTHDR(&msgh, cmsg))
		{
			if ((cmsg->cmsg_level == IPPROTO_IPV6)
			&& (cmsg->cmsg_type == IPV6_PKTINFO))
			{
				pi = (struct in6_pktinfo *) CMSG_DATA(cmsg);
				msg->dst = pi->ipi6_addr;
				msg->src = (&from)->sin6_addr;
				break;
			}
		}
	}

	logmsg(LOG_FULLTRACE, "%s exiting", __func__);
	return i;
}

ssize_t lc_msg_send(lc_channel_t *channel, lc_message_t *msg)
{
	logmsg(LOG_TRACE, "%s", __func__);
	if (channel == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_CHANNEL_REQUIRED);
	if (channel->address == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_INVALID_PARAMS);
	if (channel->socket == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_SOCKET_REQUIRED);
	if (msg == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_MESSAGE_REQUIRED);
	if (msg->len > 0 && msg->data == NULL)
		return lc_error_log(LOG_ERROR, LC_ERROR_MESSAGE_EMPTY);

	struct addrinfo *addr = channel->address;
	int sock = channel->socket->socket;
	int opt = 1;
	lc_message_head_t *head = NULL;
	char *buf = NULL;
	size_t len = 0;
	ssize_t bytes = 0;
	struct timespec t;

	head = calloc(1, sizeof(lc_message_head_t));
	if (msg->timestamp != 0){
		head->timestamp = htobe64(msg->timestamp);
	}
	else if (clock_gettime(CLOCK_REALTIME, &t) == 0) {
		head->timestamp = htobe64(t.tv_sec * 1000000000 + t.tv_nsec);
	}
	logmsg(LOG_DEBUG, "nanostamp: %"PRIu64"", be64toh(head->timestamp));
	head->seq = htobe64(++channel->seq);
	lc_getrandom(&head->rnd, sizeof(lc_rnd_t), 0);
	head->len = htobe64(msg->len);
	head->op = msg->op;
	len = msg->len;

	logmsg(LOG_DEBUG, "sending message with OPCODE %i", msg->op);

	buf = calloc(1, sizeof(lc_message_head_t) + len);
	memcpy(buf, head, sizeof(lc_message_head_t));
	memcpy(buf + sizeof(lc_message_head_t), msg->data, len);

	len += sizeof(lc_message_head_t);

	/* use tap iface if available */
	opt = (channel->ctx->tapname) ? if_nametoindex(channel->ctx->tapname) : 0;
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &opt,
			sizeof(opt) == 0))
	{
		if (channel->ctx->tapname)
			logmsg(LOG_DEBUG, "Sending on interface %s", channel->ctx->tapname);
		else
			logmsg(LOG_DEBUG, "Sending on default interface");
		bytes = sendto(sock, buf, len, 0, addr->ai_addr, addr->ai_addrlen);
		logmsg(LOG_DEBUG, "Sent %i bytes", (int)bytes);
	}
	free(head);
	free(buf);

	return bytes;
}

int lc_getrandom(void *buf, size_t buflen, unsigned int flags)
{
	int fd;
	int err = 0;
	size_t len;

	if ((fd = open("/dev/urandom", O_RDONLY)) == -1)
		return lc_error_log(LOG_ERROR, LC_ERROR_RANDOM_OPEN);
	if ((len = read(fd, buf, buflen)) == -1) {
		err = lc_error_log(LOG_ERROR, LC_ERROR_RANDOM_READ);
	}
	close(fd);

	return err;
}
