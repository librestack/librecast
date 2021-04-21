/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2017-2021 Brett Sheffield <bacs@librecast.net> */

#include <librecast/if.h>
#include "librecast_pvt.h"

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>

static inline int lc_ctrl_socket(void)
{
	return socket(AF_LOCAL, SOCK_STREAM, 0);
}

int lc_bridge_del(lc_ctx_t *ctx, const char *brname)
{
	(void)ctx; (void)brname;
	return ENOTSUP;
}

int lc_bridge_add(lc_ctx_t *ctx, const char *brname)
{
	(void)ctx; (void)brname;
	return ENOTSUP;
}

int lc_bridge_delif(lc_ctx_t *ctx, const char *brname, const char *ifname)
{
	(void)ctx; (void)brname; (void)ifname;
	return ENOTSUP;
}

int lc_bridge_addif(lc_ctx_t *ctx, const char *brname, const char *ifname)
{
	(void)ctx; (void)brname; (void)ifname;
	return ENOTSUP;
}

int lc_link_set(lc_ctx_t *ctx, char *ifname, int up)
{
	struct ifreq ifr;
	int err = 0;

	if (ctx->sock == -1) ctx->sock = lc_ctrl_socket();
	if (ctx->sock == -1) return -1;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(ctx->sock, SIOCGIFFLAGS, &ifr) == -1) {
		return -1;
	}
	ifr.ifr_flags = (up) ? ifr.ifr_flags | IFF_UP
			     : ifr.ifr_flags & ~IFF_UP;
	err = ioctl(ctx->sock, SIOCSIFFLAGS, &ifr);

	return err;
}

int lc_tap_create(char *ifname)
{
	(void)ifname;
	return ENOTSUP;
}
