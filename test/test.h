/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "misc.h"
#include "falloc.h"
#include "valgrind.h"
#ifdef __linux__
#include <linux/capability.h>
#else
#define CAP_NET_ADMIN 12
#endif

extern int fails;

void fail_msg(char *msg, ...);
int test_assert(int condition, char *msg, ...);
int test_strcmp(char *str1, char *str2, char *msg, ...);
int test_strncmp(char *str1, char *str2, size_t len, char *msg, ...);
int test_expect(char *expected, char *got);
int test_expectn(char *expected, char *got, size_t len);
void test_log(char *msg, ...);
void test_name(char *str, ...);
void test_cap_require(int cap);
void test_require_linux(void);
