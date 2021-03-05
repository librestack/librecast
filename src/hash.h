/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _HASH_H
#define _HASH_H 1

#include "config.h"

#if (HASH_TYPE == HASH_BLAKE2)
#include <sodium.h>
#define HASHSIZE crypto_generichash_BYTES
typedef crypto_generichash_state hash_state;
#elif (HASH_TYPE == HASH_BLAKE3)
#include <blake3.h>
#define HASHSIZE BLAKE3_OUT_LEN
typedef blake3_hasher hash_state;
char * sodium_bin2hex(char *const hex, const size_t hex_maxlen,
        const unsigned char *const bin, const size_t bin_len);
#endif

#include <librecast/crypto.h>

#define HEXLEN HASHSIZE * 2 + 1

#endif /* _HASH_H */
