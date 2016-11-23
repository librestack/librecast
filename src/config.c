#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "errors.h"
#include "log.h"

typedef struct keyval_t {
	char *key;
	char *val;
	struct keyval_t *next;
} keyval_t;

keyval_t *config;

void config_defaults()
{
#define X(key, type, val, desc) config_set(key, val);
CONFIG_DEFAULTS(X)
#undef X
}

void config_free()
{
	keyval_t *c = config;
	keyval_t *n;
	while (c != '\0') {
		n = c;
		c = c->next;
		free (n->key);
		free (n->val);
		free (n);
	}
}

void * config_get(char *key)
{
	keyval_t *c = config;
	while (c != '\0') {
		if (strcmp(key, c->key) == 0)
			return c->val;
		c = c->next;
	}
	return NULL;
}

long long config_min(char *key)
{

	CONFIG_LIMITS(CONFIG_MIN)
	return LLONG_MIN;
}

long long config_max(char *key)
{

	CONFIG_LIMITS(CONFIG_MAX)
	return LLONG_MAX;
}

void config_print(int fd)
{
	keyval_t *c = config;
	while (c != '\0') {
		dprintf(fd, "%s = %s\n", c->key, c->val);
		c = c->next;
	}
}

void config_read()
{
	char *conffile = config_get("configfile");
	logmsg(LOG_INFO, "reading config file '%s'", conffile);
}

int config_set(char *key, void *val)
{
	keyval_t *c = config;
	keyval_t *p = c;
	keyval_t *n;
	config_type_t type = config_type(key);
	long long min, max, llval;

	/* check proposed value is within upper and lower bounds */
	if (type == CONFIG_TYPE_INT) {
		errno = 0;
		llval = strtoll(val, NULL, 10);
		if (errno != 0)
			return ERROR_CONFIG_NOTNUMERIC;
		min = config_min(key);
		max = config_max(key);
		if (llval < min || llval > max)
			return ERROR_CONFIG_BOUNDS;
	}
	while (c != '\0') {
		p = c;
		c = c->next;
	}
	n = calloc(sizeof(keyval_t), 1);
	n->key = strdup(key);
	n->val = strdup(val);
	if (config == '\0')
		config = n;
	else
		p->next = n;

	return 0;
}

config_type_t config_type(char *key)
{

	CONFIG_DEFAULTS(CONFIG_TYPE)
	return 0;
}
