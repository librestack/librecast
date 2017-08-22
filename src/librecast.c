#define _GNU_SOURCE
#include "../include/librecast.h"
#include <libbridge.h>
#include "pid.h"
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

typedef struct lc_ctx_t {
	lc_ctx_t *next;
	uint32_t id;
	int fdtap;
	char *tapname;
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
	uint32_t id;
} lc_channel_t;

/* structure to pass to socket listening thread */
typedef struct lc_socket_call_t {
	lc_socket_t *sock;
	void (*callback_msg)(lc_message_t*);
	void (*callback_err)(int);
} lc_socket_call_t;

uint32_t ctx_id = 0;
uint32_t sock_id = 0;
uint32_t chan_id = 0;

lc_ctx_t *ctx_list = NULL;
lc_socket_t *sock_list = NULL;
lc_channel_t *chan_list = NULL;

#define BUFSIZE 1024
#define DEFAULT_ADDR "ff3e::"
#define DEFAULT_PORT "4242"

/* socket listener thread */
void *lc_socket_listen_thread(void *sc);

int lc_bridge_init()
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
	int fd, err = 0;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		err = errno;
		logmsg(LOG_ERROR, "failed to create ioctl socket: %s", strerror(err));
		return LC_ERROR_SOCK_IOCTL;
	}
        memset(&ifr, 0, sizeof(ifr));
        memcpy(ifr.ifr_name, ifname, strlen(ifname));
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

lc_ctx_t * lc_ctx_new()
{
	logmsg(LOG_TRACE, "%s", __func__);
	lc_ctx_t *ctx, *p;

	/* FIXME: randomize ids  - replace with proper hashing */
	time_t t;
	srand((unsigned)time(&t));
	ctx_id = rand() % UINT32_MAX;
	sock_id = rand() % UINT32_MAX;
	chan_id = rand() % UINT32_MAX;

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
		free(ctx);
		return NULL;
	}
        logmsg(LOG_DEBUG, "bridging interface %s to bridge %s", tap, LC_BRIDGE_NAME);
	/* plug TAP into bridge */
	if ((lc_bridge_add_interface(LC_BRIDGE_NAME, tap)) == -1) {
		lc_error_log(LOG_ERROR, LC_ERROR_IF_BRIDGE_FAIL);
		lc_ctx_free(ctx);
		return NULL;
	}

	ctx->tapname = tap;
	ctx->fdtap = fdtap;

	return ctx;
}

uint32_t lc_ctx_get_id(lc_ctx_t *ctx)
{
	logmsg(LOG_TRACE, "%s", __func__);

	if (ctx == NULL)
		lc_error_log(LOG_ERROR, LC_ERROR_CTX_REQUIRED);
		return 0;

	return ctx->id;
}

uint32_t lc_socket_get_id(lc_socket_t *sock)
{
	logmsg(LOG_TRACE, "%s", __func__);
	return sock->id;
}

uint32_t lc_channel_get_id(lc_channel_t *chan)
{
	logmsg(LOG_TRACE, "%s", __func__);
	return chan->id;
}

void lc_ctx_free(lc_ctx_t *ctx)
{
	logmsg(LOG_TRACE, "%s", __func__);
	if (ctx) {
		if (ctx->tapname)
			free(ctx->tapname);
		close(ctx->fdtap);
		free(ctx);
	}
}

lc_socket_t * lc_socket_new(lc_ctx_t *ctx)
{
	logmsg(LOG_TRACE, "%s", __func__);
	lc_socket_t *sock, *p;
	int s;

	sock = calloc(1, sizeof(lc_socket_t));
	sock->ctx = ctx;
	sock->id = ++sock_id;
	for (p = sock_list; p != NULL; p = p->next) {
		if (p->next == NULL)
			p->next = sock;
	}
	s = socket(AF_INET6, SOCK_DGRAM, 0);
	int err = errno;
	if (s == -1)
		logmsg(LOG_DEBUG, "socket ERROR: %s", strerror(err));
	else
		sock->socket = s;
	logmsg(LOG_DEBUG, "socket %i created with id %u", sock->socket, sock->id);

	return sock;
}

int lc_socket_listen(lc_socket_t *sock, void (*callback_msg)(lc_message_t*),
                                        void (*callback_err)(int))
{
	logmsg(LOG_TRACE, "%s", __func__);
	pthread_attr_t attr = {};
	lc_socket_call_t *sc;

	sc = calloc(1, sizeof(lc_socket_call_t));
	sc->sock = sock;
	sc->callback_msg = callback_msg;
	sc->callback_err = callback_err;

	/* existing listener on socket */
	if (sock->thread != 0)
		return lc_error_log(LOG_DEBUG, LC_ERROR_SOCKET_LISTENING);

	pthread_attr_init(&attr);
	pthread_create(&(sock->thread), &attr, lc_socket_listen_thread, sc);
	pthread_attr_destroy(&attr);

	return 0;
}

int lc_socket_listen_cancel(lc_socket_t *sock)
{
	logmsg(LOG_TRACE, "%s", __func__);
	if (sock->thread != 0) {
		pthread_cancel(sock->thread);
		pthread_join(sock->thread, NULL);
		sock->thread = 0;
	}

	return 0;
}

void *lc_socket_listen_thread(void *arg)
{
	logmsg(LOG_TRACE, "%s", __func__);
	ssize_t len;
	lc_message_t *msg = calloc(1, sizeof(lc_message_t));
	lc_socket_call_t *sc = arg;

	while(1) {
		msg = calloc(1, sizeof(lc_message_t));
		len = lc_msg_recv(sc->sock, &msg->msg);
		logmsg(LOG_DEBUG, "got data %i bytes", (int)len);
		if (len > 0) {
			msg->sockid = sc->sock->id;
			logmsg(LOG_DEBUG, "msg->sockid set to %u", sc->sock->id);
			msg->len = len;
			/* TODO: include dest address etc. */
			if (sc->callback_msg)
				sc->callback_msg(msg);
		}
		if (len < 0)
			free(msg);
			if (sc->callback_err)
				sc->callback_err(len);
		free(msg->msg);
		free(msg);
	}
	/* not reached */
	return NULL;
}

void lc_socket_close(lc_socket_t *sock)
{
	logmsg(LOG_TRACE, "%s", __func__);
	if (sock)
		if (sock->socket)
			close(sock->socket);
	free(sock);
}

lc_channel_t * lc_channel_new(lc_ctx_t *ctx, char * url)
{
	logmsg(LOG_TRACE, "%s", __func__);
	lc_channel_t *channel, *p;
	struct addrinfo *addr = NULL;
	struct addrinfo hints = {0};

	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	if (getaddrinfo(DEFAULT_ADDR, DEFAULT_PORT, &hints, &addr) != 0) {
		return NULL;
	}

	channel = calloc(1, sizeof(lc_channel_t));
	channel->ctx = ctx;
	channel->id = ++chan_id;
	channel->address = addr;
	for (p = chan_list; p != NULL; p = p->next) {
		if (p->next == NULL)
			p->next = channel;
	}

	return channel;
}

int lc_channel_bind(lc_socket_t *sock, lc_channel_t * channel)
{
	logmsg(LOG_TRACE, "%s", __func__);
	struct addrinfo *addr = channel->address;
	int err, opt;

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
	int sock = channel->socket->socket;
	struct addrinfo *addr = channel->address;
	int joins = 0;

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
		req.ipv6mr_interface = if_nametoindex(ifa->ifa_name);
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &req,
					sizeof(req)) != 0)
		{
			logmsg(LOG_ERROR, "Multicast join failed on %s", ifa->ifa_name);
		}
		else {
			logmsg(LOG_DEBUG, "Multicast join succeeded on %s", ifa->ifa_name);
			joins++;
		}
	}
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
	freeaddrinfo(channel->address);
	free(channel);
	return 0;
}

ssize_t lc_msg_recv(lc_socket_t *sock, char **msg)
{
	logmsg(LOG_TRACE, "%s", __func__);
	int i;
	char dstaddr[INET6_ADDRSTRLEN];
	struct iovec iov;
	struct msghdr msgh;
	char cmsgbuf[BUFSIZE];
	struct sockaddr_in from;
	socklen_t fromlen = sizeof(from);
	struct cmsghdr *cmsg;
	struct in6_pktinfo *pi;
	struct in6_addr da;

	assert(sock != NULL);

	*msg = calloc(1, BUFSIZE);

	memset(&msgh, 0, sizeof(struct msghdr));
	iov.iov_base = *msg;
        iov.iov_len = BUFSIZE - 1;
        msgh.msg_control = cmsgbuf;
        msgh.msg_controllen = BUFSIZE - 1;
        msgh.msg_name = &from;
        msgh.msg_namelen = fromlen;
        msgh.msg_iov = &iov;
        msgh.msg_iovlen = 1;
        msgh.msg_flags = 0;

	logmsg(LOG_DEBUG, "recvmsg on sock = %i", sock->socket);
	i = recvmsg(sock->socket, &msgh, 0);
	int err = errno;
	if (i == -1) {
		logmsg(LOG_DEBUG, "recvmsg ERROR: %s", strerror(err));
	}
        if (i > 0) {
                dstaddr[0] = '\0';
                for (cmsg = CMSG_FIRSTHDR(&msgh);
                     cmsg != NULL;
                     cmsg = CMSG_NXTHDR(&msgh, cmsg))
                {
                        if ((cmsg->cmsg_level == IPPROTO_IPV6)
                          && (cmsg->cmsg_type == IPV6_PKTINFO))
                        {
                                pi = (struct in6_pktinfo *) CMSG_DATA(cmsg);
                                da = pi->ipi6_addr;
                                inet_ntop(AF_INET6, &da, dstaddr, INET6_ADDRSTRLEN);
                                break;
                        }
                }
		(*msg)[i + 1] = '\0';
        }

	logmsg(LOG_FULLTRACE, "recvmsg exiting");
	return i;
}

int lc_msg_send(lc_channel_t *channel, char *msg, size_t len)
{
	logmsg(LOG_TRACE, "%s", __func__);
	struct addrinfo *addr = channel->address;
	int sock = channel->socket->socket;
	int opt = 1;

	/* set loopback */
	setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &opt,sizeof(opt));
	opt = if_nametoindex(channel->ctx->tapname);
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &opt,
			sizeof(opt) == 0))
	{
	logmsg(LOG_DEBUG, "Sending on interface %s", channel->ctx->tapname);
	sendto(sock, msg, len, 0, addr->ai_addr, addr->ai_addrlen);
	}

	return 0;
}

int lc_librecast_running()
{
	logmsg(LOG_TRACE, "%s", __func__);
	int lockfd = 0;
	int ret = 0;
	long pid = 0;
	char buf[sizeof(long)] = "";

	if ((lockfd = obtain_lockfile(O_RDONLY)) == -1) {
		return LIBRECASTD_NOT_RUNNING;
	}
	if (pread(lockfd, &buf, sizeof(buf), 1) == -1) {
		return LIBRECASTD_NOT_RUNNING;
	}
	if (sscanf(buf, "%li", &pid) != 1) {
		return LIBRECASTD_NOT_RUNNING;
	}
	ret = kill(pid, 0);

	return (ret == 0) ? LIBRECASTD_RUNNING : LIBRECASTD_NOT_RUNNING;
}
