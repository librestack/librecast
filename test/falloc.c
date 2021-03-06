/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2021 Brett Sheffield <bacs@librecast.net> */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile int allock;
static size_t stackptr;
static char stackbuf[1024];
static void *(*_malloc)(size_t);
static void (*_free)(void *);
static int falloc_fail = -1; /* *alloc fails when zero - decremented each allocation */

static void *falloc_enomem(void)
{
	fprintf(stderr, "falloc forcing ENOMEM\n");
	errno = ENOMEM;
	return NULL;
}

void *malloc(size_t size)
{
	if (allock) {
		/* thanks to FatalFlaw for the idea
		 * https://stackoverflow.com/questions/6083337/overriding-malloc-using-the-ld-preload-mechanism */
		/* dlsym calls calloc() - hand it a block from our stack */
		void *p;
		p = stackbuf + stackptr;
		stackptr += size;
		return p;
	}
	else if (!_malloc) {
		allock = 1;
		*(void **)&_malloc = dlsym(RTLD_NEXT, "malloc");
		*(void **)&_free = dlsym(RTLD_NEXT, "free");
		allock = 0;
	}
	if (falloc_fail > 0) falloc_fail--;
	if (!falloc_fail) return falloc_enomem();
	return _malloc(size);
}

void *calloc(size_t nmemb, size_t size)
{
	void *ptr;
	size_t sz = nmemb * size;
	ptr = malloc(sz);
	if (!ptr) return NULL;
	memset(ptr, 0, sz);
	return ptr;
}

void free(void *ptr)
{
	if ((char *)ptr < stackbuf || (char *)ptr > stackbuf + sizeof stackbuf)
		_free(ptr);
}

void falloc_setfail(int failafter)
{
	falloc_fail = failafter;
}
