#include <stdlib.h>
#include <string.h>
#include "config.h"

typedef struct keyval_t {
	char *key;
	char *val;
	struct keyval_t *next;
} keyval_t;

keyval_t *config;

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

void config_set(char *key, void *val)
{
	keyval_t *c = config;
	keyval_t *p = c;
	keyval_t *n;
	while (c != '\0') {
		p = c;
		c = c->next;
	}
	n = calloc(sizeof(struct keyval_t), 1);
	n->key = strdup(key);
	n->val = strdup(val);
	if (config == '\0')
		config = n;
	else
		p->next = n;
}

void free_config()
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
