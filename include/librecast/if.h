/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2017-2022 Brett Sheffield <bacs@librecast.net> */

#ifndef _LIBRECAST_IF_H
#define _LIBRECAST_IF_H 1

#include <librecast/types.h>
#include <net/if.h>
#ifdef __linux__
#include <linux/if_tun.h>
#endif

#ifndef IFF_UP
#define       IFF_UP          0x1
#endif

#define LC_IF_UP              IFF_UP
#define LC_IF_DOWN            0x0

/* create / destroy bridge */
int lc_bridge_add(lc_ctx_t *ctx, const char *brname);
int lc_bridge_del(lc_ctx_t *ctx, const char *brname);

/* add / remove interface ifname from bridge brname */
int lc_bridge_addif(lc_ctx_t *ctx, const char *brname, const char *ifname);
int lc_bridge_delif(lc_ctx_t *ctx, const char *brname, const char *ifname);

/* create new tun/tap interface. Set ifname as interface name, if provided,
 * otherwise returns the O/S generated name in this buffer.
 * ifname must be a char array if size IFNAMSIZ.
 *
 * Flags: IFF_TUN   - TUN device (no Ethernet headers)
 *        IFF_TAP   - TAP device
 *
 *        IFF_NO_PI - Do not provide packet information
 *        IFF_MULTI_QUEUE - Create a queue of multiqueue device
 */
int lc_tuntap_create(char *ifname, int flags);

/* Wrapper for lc_tuntap_create() - create new tap device and copy interface
 * name to ifname, which must be a buffer of size IFNAMSIZ. */
int lc_tap_create(char *ifname);

/* Bring up / tear down interface called ifname
 * up = LC_IF_UP   - bring interface up
 * up = LC_IF_DOWN - bring interface down */
int lc_link_set(lc_ctx_t *ctx, char *ifname, int up);

#endif /* _LIBRECAST_IF_H */
