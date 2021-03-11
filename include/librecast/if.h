/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2017-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _LIBRECAST_IF_H
#define _LIBRECAST_IF_H 1

#include <librecast/types.h>

/* create / destroy bridge */
int lc_bridge_add(lc_ctx_t *ctx, const char *brname);
int lc_bridge_del(lc_ctx_t *ctx, const char *brname);

/* create new tap device and copy interface name to ifname, which must be a buffer of size IFNAMSIZ. */
int lc_tap_create(char *ifname);

#endif /* _LIBRECAST_IF_H */
