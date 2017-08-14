#define _GNU_SOURCE
#include "../include/librecast.h"
#include "pid.h"
#include "errors.h"
#include "log.h"
#include <assert.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct lc_ctx_t {
	int id;
} lc_ctx_t;

typedef struct lc_socket_t {
	int socket;
	pthread_t thread;
} lc_socket_t;

typedef struct lc_channel_t {
	struct lc_socket_t *socket;
	struct addrinfo *address;
} lc_channel_t;

/* structure to pass to socket listening thread */
typedef struct lc_socket_call_t {
	lc_socket_t *sock;
	void (*callback_msg)(char *, ssize_t);
	void (*callback_err)(int);
} lc_socket_call_t;

#define BUFSIZE 1024
#define DEFAULT_ADDR "ff3e::"
#define DEFAULT_PORT "4242"

/* socket listener thread */
void *lc_socket_listen_thread(void *sc);

lc_ctx_t * lc_ctx_new()
{
	lc_ctx_t *ctx;
	ctx = calloc(1, sizeof(lc_ctx_t));
	return ctx;
}

void lc_ctx_free(lc_ctx_t *ctx)
{
	free(ctx);
}

lc_socket_t * lc_socket_new(lc_ctx_t *ctx)
{
	lc_socket_t *sock;
	int s;

	sock = calloc(1, sizeof(lc_socket_t));
	assert(sock);
	s = socket(AF_INET6, SOCK_DGRAM, 0);
	int err = errno;
	if (s == -1)
		logmsg(LOG_DEBUG, "socket ERROR: %s", strerror(err));
	else
		sock->socket = s;

	return sock;
}

int lc_socket_listen(lc_socket_t *sock, void (*callback_msg)(char *, ssize_t),
		void (*callback_err)(int))
{
	pthread_attr_t attr = {};
	lc_socket_call_t *sc;

	sc = calloc(1, sizeof(lc_socket_call_t));
	sc->sock = sock;
	sc->callback_msg = callback_msg;
	sc->callback_err = callback_err;

	/* existing listener on socket */
	if (sock->thread != 0)
		return ERROR_SOCKET_LISTENING;

	pthread_attr_init(&attr);
	pthread_create(&(sock->thread), &attr, lc_socket_listen_thread, sc);
	pthread_attr_destroy(&attr);

	return 0;
}

int lc_socket_listen_cancel(lc_socket_t *sock)
{
	if (sock->thread != 0) {
		pthread_cancel(sock->thread);
		pthread_join(sock->thread, NULL);
		sock->thread = 0;
	}

	return 0;
}

void *lc_socket_listen_thread(void *arg)
{
	ssize_t len;
	char *msg = NULL;
	lc_socket_call_t *sc = arg;

	while(1) {
		len = lc_msg_recv(sc->sock, &msg);
		logmsg(LOG_DEBUG, "got data %i bytes", (int)len);
		if (len > 0) {
			if (sc->callback_msg)
				sc->callback_msg(msg, len);
			free(msg);
		}
		if (len < 0)
			if (sc->callback_err)
				sc->callback_err(len);
	}
	/* not reached */
	return NULL;
}

void lc_socket_close(lc_socket_t *sock)
{
	if (sock)
		if (sock->socket)
			close(sock->socket);
	free(sock);
}

lc_channel_t * lc_channel_new(lc_ctx_t *ctx, char * url)
{
	lc_channel_t *channel;
	struct addrinfo *addr = NULL;
	struct addrinfo hints = {0};

	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	if (getaddrinfo(DEFAULT_ADDR, DEFAULT_PORT, &hints, &addr) != 0) {
		return NULL;
	}

	channel = calloc(1, sizeof(lc_channel_t));
	channel->address = addr;

	return channel;
}

int lc_channel_bind(lc_socket_t *sock, lc_channel_t * channel)
{
	struct addrinfo *addr = channel->address;

	channel->socket = sock;
	if (bind(sock->socket, addr->ai_addr, addr->ai_addrlen) != 0) {
		logmsg(LOG_ERROR, "Unable to bind to socket %i", sock->socket);
		return ERROR_SOCKET_BIND;
	}

	return 0;
}

int lc_channel_unbind(lc_channel_t * channel)
{
	channel->socket = NULL;
	return 0;
}

int lc_channel_join(lc_channel_t * channel)
{
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
	return ERROR_MCAST_JOIN;
}

int lc_channel_leave(lc_channel_t * channel)
{
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
		return ERROR_MCAST_LEAVE;
	}

	return 0;
}

lc_socket_t *lc_channel_socket(lc_channel_t *channel)
{
	return channel->socket;
}

int lc_channel_socket_raw(lc_channel_t *channel)
{
	return channel->socket->socket;
}

int lc_socket_raw(lc_socket_t *sock)
{
	return sock->socket;
}

int lc_channel_free(lc_channel_t * channel)
{
	freeaddrinfo(channel->address);
	free(channel);
	return 0;
}

ssize_t lc_msg_recv(lc_socket_t *sock, char **msg)
{
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

	return i;
}

int lc_msg_send(lc_channel_t *channel, char *msg, size_t len)
{
	struct addrinfo *addr = channel->address;
	struct ifaddrs *ifaddr, *ifa;
	int sock = channel->socket->socket;
	int opt = 1;

	if (getifaddrs(&ifaddr) == -1) {
		logmsg(LOG_DEBUG, "Failed to get interface list; using default");
		sendto(sock, msg, len, 0, addr->ai_addr, addr->ai_addrlen);
	}
	else {
		/* set loopback for first packet only */
		setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &opt,sizeof(opt));
		/* send to all interfaces */
		for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
			opt = if_nametoindex(ifa->ifa_name);

			if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &opt,
					sizeof(opt) == 0))
			{
				logmsg(LOG_DEBUG, "Sending on interface %s", ifa->ifa_name);
				sendto(sock, msg, len, 0, addr->ai_addr, addr->ai_addrlen);
			}
			opt = 0; /* disable loopback after first interface */
			setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &opt,sizeof(opt));
		}
	}

	return 0;
}

int lc_librecast_running()
{
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
