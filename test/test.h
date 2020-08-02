/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "../src/misc.h"

extern int fails;

void fail_msg(char *msg, ...);
void test_assert(int condition, char *msg, ...);
void test_strcmp(char *str1, char *str2, char *msg, ...);
void test_strncmp(char *str1, char *str2, size_t len, char *msg, ...);
void test_expect(char *expected, char *got);
void test_expectn(char *expected, char *got, size_t len);
void test_log(char *msg, ...);
void test_name(char *str, ...);
