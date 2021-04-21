/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

/* wrappers for *alloc */
void *calloc(size_t nmemb, size_t size);
void *malloc(size_t size);

/* set *alloc calls to force failure with ENOMEM after failafter allocations.
 * Set failafter to -1 to never force fail (default) */
void falloc_setfail(int failafter);
