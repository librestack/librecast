#ifndef __LIBRECAST_CONFIG_H__
#define __LIBRECAST_CONFIG_H__ 1

typedef enum {
	CONFIG_TYPE_INVALID,
	CONFIG_TYPE_BOOL,
	CONFIG_TYPE_INT,
	CONFIG_TYPE_STRING
} config_type_t;

#define CONFIG_DEFAULTS(X) \
	X("configfile", CONFIG_TYPE_STRING, "/etc/librecast.conf", "path to config file") \
	X("loglevel", CONFIG_TYPE_INT, "127", "logging level") \
	X("daemon", CONFIG_TYPE_BOOL, "0", "run as daemon") \
	X("dropprivs", CONFIG_TYPE_BOOL, "1", "drop root privileges") \
	X("castaddr", CONFIG_TYPE_INT, "ff15::1", "multicast addr") \
	X("castport", CONFIG_TYPE_INT, "4242", "multicast port")
#undef X

/* lower and upper bounds on numeric config types */
#define CONFIG_LIMITS(X) \
	X("loglevel", 0, 127) \
	X("port", 1, 65535)
#undef X

#define CONFIG_TYPE(k, type, val, desc) if (strcmp(key, k) == 0) return type;
#define CONFIG_MIN(k, min, max) if (strcmp(key, k) == 0) return min;
#define CONFIG_MAX(k, min, max) if (strcmp(key, k) == 0) return max;

/* convert true/false yes/no to 1 (true) or 0 (false).  Return 0 or error */
int config_bool_convert(char *val, long long *llval);

/* set configuration defaults, before overriding with any options or reading
 * a configuration file */
void config_defaults();

/* free config memory */
void config_free();

/* get a config value by name */
void * config_get(char *key);

/* get a numeric config value by name */
long long config_get_num(char * key);

/* return 1 if config type is numeric, 0 if not */
int config_numeric(char * key);

/* output currently loaded configuration to file descriptor */
void config_print(int fd);

/* process an individual config file line. Return 0 or error */
int config_process_line(char *line);

/* read and process a configuration file. Return 0 or error */
int config_read();

/* reload configuration file */
int config_reload();

/* set a config key/value pair.  Returns 0 or error code */
int config_set(char *key, void *val);

/* set a numeric config key/value pair.  Returns 0 or error code */
int config_set_num(char *key, long long llval);

/* lookup type of config item */
config_type_t config_type(char *k);

/* perform necessary validation checks on config settings */
int config_validate_option(char *key, char *val);

#endif /* __LIBRECAST_CONFIG_H__ */
