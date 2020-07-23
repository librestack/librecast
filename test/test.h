#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "../src/misc.h"
#include "../include/librecast.h"

extern int fails;

void fail_msg(char *msg, ...);
void test_assert(int condition, char *msg, ...);
void test_strcmp(char *str1, char *str2, char *msg, ...);
void test_expect(char *expected, char *got);
void result(char *str);
