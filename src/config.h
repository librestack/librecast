/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef LIBRECAST_CONFIG_H
#define LIBRECAST_CONFIG_H 1

#define HASH_BLAKE2 2
#define HASH_BLAKE3 3
#ifdef USE_LIBSODIUM
#define HASH_TYPE HASH_BLAKE2
#else
#define HASH_TYPE HASH_BLAKE3
#endif

#endif /* LIBRECAST_CONFIG_H */
