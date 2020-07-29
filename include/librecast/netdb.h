/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2017-2020 Brett Sheffield <bacs@librecast.net> */
/* librecast/netdb.h - network database functions
 * for direct-access database functions see <librecast/db.h>
 */

#ifndef _LIBRECAST_NETDB_H
#define _LIBRECAST_NETDB_H 1

#include <librecast/types.h>

/* data storage functions */
int lc_channel_getval(lc_channel_t *chan, lc_val_t *key);
int lc_channel_setval(lc_channel_t *chan, lc_val_t *key, lc_val_t *val);

#endif /* _LIBRECAST_NETDB_H */
