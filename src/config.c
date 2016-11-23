#define _GNU_SOURCE
#include <assert.h>
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

int config_bool_convert(char *val, long long *llval)
{
	int i;
	char *truth[] = { "1", "true", "yes", "on" };
	char *falsy[] = { "0", "false", "no", "off" };
	for (i = 0; i < sizeof(truth) / sizeof(char *); i++) {
		if (strcmp(val, truth[i]) == 0) {
			*llval = 1;
			return 0;
		}
	}
	for (i = 0; i < sizeof(falsy) / sizeof(char *); i++) {
		if (strcmp(val, falsy[i]) == 0) {
			*llval = 0;
			return 0;
		}
	}
	return ERROR_CONFIG_BOOLEAN;
}

void config_defaults()
{
#define X(key, type, val, desc) assert(config_set(key, val) == 0);
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

long long config_get_num(char * key)
{
	char *val;
	long long llval;

	assert(config_numeric(key));
	val = config_get(key);
	assert(val != NULL);
	llval = strtoll(val, NULL, 10);

	return llval;
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

int config_numeric(char * key)
{
	config_type_t type = config_type(key);
	return (type == CONFIG_TYPE_BOOL || type == CONFIG_TYPE_INT) ? 1 : 0;
}

void config_print(int fd)
{
	keyval_t *c = config;
	while (c != '\0') {
		dprintf(fd, "%s %s\n", c->key, c->val);
		c = c->next;
	}
}

int config_process_line(char *line)
{
	char key[LINE_MAX], value[LINE_MAX];
	long long llval;

	if (line[0] == '#') {
		logmsg(LOG_DEBUG, "config_process_line: skipping comment");
	}
	else if (sscanf(line, "%s %lli", key, &llval) == 2) {
		logmsg(LOG_DEBUG, "config_process_line: numeric config line");
		return config_set_num(key, llval);
	}
	else if (sscanf(line, "%[a-zA-Z0-9]", value) == 0) {
		logmsg(LOG_DEBUG, "config_process_line: skipping blank line");
	}
	else {
		return ERROR_CONFIG_INVALID;
	}

	return 0;
}

int config_read(char *configfile)
{
	FILE *fd;
	char line[LINE_MAX];
	int lc = 0;
	int e = 0;

	if (configfile == NULL)
		configfile = config_get("configfile");

	logmsg(LOG_INFO, "reading config file '%s'", configfile);

	/* open config file */
	fd = fopen(configfile, "r");
	if (fd == NULL) {
		int errsv = errno;
		logmsg(LOG_ERROR, strerror(errsv));
		errno = 0;
		return ERROR_CONFIG_READFAIL;
	}

	/* read line by line */
	while (fgets(line, LINE_MAX, fd) != NULL) {
		lc++;
		if ((e = config_process_line(line))) {
			logmsg(LOG_ERROR, "error in line %i of config file",lc);
			goto config_read_done;
		}
	}

config_read_done:
	/* tidy up */
	fclose(fd);

	return e;
}

int config_set(char *key, void *val)
{
	keyval_t *c = config;
	keyval_t *p = c;
	keyval_t *n;
	config_type_t type = config_type(key);
	long long min, max, llval;

	if (type == CONFIG_TYPE_INVALID) {
		logmsg(LOG_ERROR, "'%s' not a valid configuration option", key);
		return ERROR_CONFIG_INVALID;
	}
	else if (type == CONFIG_TYPE_BOOL) {
		if (config_bool_convert(val, &llval) != 0)
			return ERROR_CONFIG_BOOLEAN;
	}
	else if (type == CONFIG_TYPE_INT) {
		/* check proposed value is within upper and lower bounds */
		errno = 0;
		llval = strtoll(val, NULL, 10);
		if (errno != 0)
			return ERROR_CONFIG_NOTNUMERIC;
		min = config_min(key);
		max = config_max(key);
		if (llval < min || llval > max)
			return ERROR_CONFIG_BOUNDS;
	}

	/* set value */
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

int config_set_num(char *key, long long llval)
{
	char *val;
	int e;

	if (asprintf(&val, "%lli", llval) == -1) {
		int errsv = errno;
		print_error(0, errsv, "config_set_num");
		return ERROR_MALLOC;
	}
	e = config_set(key, val);
	free(val);

	return e;
}

config_type_t config_type(char *key)
{

	CONFIG_DEFAULTS(CONFIG_TYPE)
	return CONFIG_TYPE_INVALID;
}
