/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2017-2021 Brett Sheffield <bacs@librecast.net> */

/* Contains code derived from libbridge (part of bridge-utils)
 * Copyright (C) 2000-2017 Lennert Buytenhek, Stephen Hemminger et al */

#include <librecast/if.h>
#include "librecast_pvt.h"

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>

#ifdef __linux__
#include <linux/if.h>
#include <linux/if_bridge.h>
#include <linux/if_tun.h>
#endif

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
	int ret;

	if (ctx->sock == -1) ctx->sock = lc_ctrl_socket();
	if (ctx->sock == -1) return -1;
#ifdef SIOCBRDELBR
	ret = ioctl(ctx->sock, SIOCBRDELBR, brname);
	if (ret < 0)
#endif
	{
		char _br[IFNAMSIZ];
		unsigned long arg[3] = { BRCTL_DEL_BRIDGE, (unsigned long) _br };
		strncpy(_br, brname, IFNAMSIZ - 1);
		ret = ioctl(ctx->sock, SIOCSIFBR, arg);
	}
	return ret < 0 ? errno : 0;
}

int lc_bridge_add(lc_ctx_t *ctx, const char *brname)
{
	int ret;

	if (ctx->sock == -1) ctx->sock = lc_ctrl_socket();
	if (ctx->sock == -1) return -1;
#ifdef SIOCBRADDBR
	ret = ioctl(ctx->sock, SIOCBRADDBR, brname);
	if (ret < 0)
#endif
	{
		char _br[IFNAMSIZ];
		unsigned long arg[3] = { BRCTL_ADD_BRIDGE, (unsigned long) _br };
		strncpy(_br, brname, IFNAMSIZ - 1);
		ret = ioctl(ctx->sock, SIOCSIFBR, arg);
	}
	return ret < 0 ? errno : 0;
}

int lc_bridge_delif(lc_ctx_t *ctx, const char *brname, const char *ifname)
{
	struct ifreq ifr;
	int err;
	int ifx = if_nametoindex(ifname);

	if (ifx == 0) return ENODEV;
	if (ctx->sock == -1) ctx->sock = lc_ctrl_socket();
	if (ctx->sock == -1) return -1;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, brname, IFNAMSIZ - 1);
#ifdef SIOCBRDELIF
	ifr.ifr_ifx = ifx;
	err = ioctl(ctx->sock, SIOCBRDELIF, &ifr);
	if (err < 0)
#endif
	{
		unsigned long args[4] = { BRCTL_DEL_IF, ifx, 0, 0 };
		ifr.ifr_data = (char *) args;
		err = ioctl(ctx->sock, SIOCDEVPRIVATE, &ifr);
	}
	return err < 0 ? errno : 0;
}

int lc_bridge_addif(lc_ctx_t *ctx, const char *brname, const char *ifname)
{
	struct ifreq ifr;
	int err;
	int ifx = if_nametoindex(ifname);

	if (ifx == 0) return ENODEV;
	if (ctx->sock == -1) ctx->sock = lc_ctrl_socket();
	if (ctx->sock == -1) return -1;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, brname, IFNAMSIZ - 1);
#ifdef SIOCBRADDIF
	ifr.ifr_ifindex = ifx;
	err = ioctl(ctx->sock, SIOCBRADDIF, &ifr);
	if (err < 0)
#endif
	{
		unsigned long args[4] = { BRCTL_ADD_IF, ifx, 0, 0 };
		ifr.ifr_data = (char *) args;
		err = ioctl(ctx->sock, SIOCDEVPRIVATE, &ifr);
	}
	return err < 0 ? errno : 0;
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
	struct ifreq ifr;
	int fd;

	if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if (ioctl(fd, TUNSETIFF, (void *) &ifr) == -1) {
		close(fd);
		return -1;
	}
	strncpy(ifname, ifr.ifr_name, IFNAMSIZ);

	return fd;
}
