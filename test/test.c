#include "test.h"

int fails = 0;

void vfail_msg(char *msg, va_list argp)
{
	char *b;
	b = malloc(_vscprintf(msg, argp) + 1);
	vsprintf(b, msg, argp);
	printf("\n            %-70s", b);
	free(b);
	fails++;
}

void fail_msg(char *msg, ...)
{
	va_list argp;
	va_start(argp, msg);
	vfail_msg(msg, argp);
	va_end(argp);
}

void test_assert(int condition, char *msg, ...)
{
	if (!condition) {
		va_list argp;
		va_start(argp, msg);
		vfail_msg(msg, argp);
		va_end(argp);
	}
}

void test_strcmp(char *str1, char *str2, char *msg, ...)
{
	if (strcmp(str1, str2)) {
		va_list argp;
		va_start(argp, msg);
		vfail_msg(msg, argp);
		va_end(argp);
	}
}

void test_expect(char *expected, char *got)
{
	test_strcmp(expected, got, "expected: '%s', got: '%s'", expected, got);
}

void result(char *str)
{
	printf("%-70s", str);
}
