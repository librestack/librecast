/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include "hash.h"

int hash_generic_key(unsigned char *hash, size_t hashlen, unsigned char *in, size_t inlen, unsigned char *key, size_t keylen)
{
	return crypto_generichash(hash, hashlen, in, inlen, key, keylen);
}

int hash_generic(unsigned char *hash, size_t hashlen, unsigned char *in, size_t inlen)
{
	return hash_generic_key(hash, hashlen, in, inlen, NULL, 0);
}

int hash_final(hash_state *state, unsigned char *hash, size_t hashlen)
{
	return crypto_generichash_final(state, hash, hashlen);
}

int hash_update(hash_state *state, unsigned char *msg, size_t msglen)
{
	return crypto_generichash_update(state, msg, msglen);
}

int hash_init(hash_state *state, unsigned char *key, size_t keylen, size_t hashlen)
{
	return crypto_generichash_init(state, key, keylen, hashlen);
}
