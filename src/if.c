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

int lc_bridge_del(lc_ctx_t *ctx, const char *brname)
{
	int ret;

	if (ctx->sock == -1) ctx->sock = socket(AF_LOCAL, SOCK_STREAM, 0);
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

	if (ctx->sock == -1) ctx->sock = socket(AF_LOCAL, SOCK_STREAM, 0);
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
