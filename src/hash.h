/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _HASH_H
#define _HASH_H 1

#include <sodium.h>
#define HASHSIZE crypto_generichash_BYTES
#define HASHMAXBYTES crypto_generichash_BYTES_MAX
#define HEXLEN HASHSIZE * 2 + 1

void hash_hex_debug(unsigned char *hash, size_t len);

/* wrapper for our hash function, in case we want to change it */
int hash_generic(unsigned char *hash, size_t hashlen, unsigned char *in, size_t inlen);
int hash_generic_key(unsigned char *hash, size_t hashlen, unsigned char *in, size_t inlen, unsigned char *key, size_t keylen);

#endif /* _HASH_H */
