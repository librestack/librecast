/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2017-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef _LIBRECAST_CRYPTO_H
#define _LIBRECAST_CRYPTO_H 1

#include <stdio.h>

#define HASH_BLAKE2 2
#define HASH_BLAKE3 3
#ifdef USE_LIBSODIUM
#define HASH_TYPE HASH_BLAKE2
#else
#define HASH_TYPE HASH_BLAKE3
#endif
#if (HASH_TYPE == HASH_BLAKE2)
#include <sodium.h>
#define HASHSIZE crypto_generichash_BYTES
typedef crypto_generichash_state hash_state;
#elif (HASH_TYPE == HASH_BLAKE3)
#include <librecast/blake3.h>
#define HASHSIZE BLAKE3_OUT_LEN
typedef blake3_hasher hash_state;
char * sodium_bin2hex(char *const hex, const size_t hex_maxlen,
        const unsigned char *const bin, const size_t bin_len);
#endif
#define hash_bin2hex sodium_bin2hex

#define HEXLEN HASHSIZE * 2 + 1

/* hash arbitrary data */
int hash_generic(unsigned char *hash, size_t hashlen, unsigned char *in, size_t inlen);

/* hash arbitrary data with using a key. Key must be 32 bytes for BLAKE3 */
int hash_generic_key(unsigned char *hash, size_t hashlen, unsigned char *in, size_t inlen, unsigned char *key, size_t keylen);

/* multi-part hash functions */
void hash_init(hash_state *state, unsigned char *key, size_t keylen, size_t hashlen);
void hash_update(hash_state *state, unsigned char *msg, size_t msglen);
void hash_final(hash_state *state, unsigned char *hash, size_t hashlen);

/* hexdump hash with length len to file descriptor fd */
void hash_hex_debug(FILE *fd, unsigned char *hash, size_t len);

#endif /* _LIBRECAST_CRYPTO_H */
