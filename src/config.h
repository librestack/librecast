#ifndef __LIBRECAST_CONFIG_H__
#define __LIBRECAST_CONFIG_H__ 1

typedef enum {
	CONFIG_TYPE_NULL,
	CONFIG_TYPE_BOOL,
	CONFIG_TYPE_INT,
	CONFIG_TYPE_LONG,
	CONFIG_TYPE_CHR,
	CONFIG_TYPE_STRING
} config_type_t;

#define CONFIG_DEFAULTS(X) \
	X("configfile", CONFIG_TYPE_STRING, "/etc/librecast.conf", "path to config file") \
	X("daemon", CONFIG_TYPE_BOOL, "0", "run as daemon") \
	X("dropprivs", CONFIG_TYPE_BOOL, "1", "drop root privileges")
#undef X

#define CONFIG_TYPE(k, type, val, desc) if (strcmp(key, k) == 0) return type;

/* set configuration defaults, before overriding with any options or reading
 * a configuration file */
void config_defaults();

/* free config memory */
void config_free();

/* get a config value by name */
void * config_get(char *key);

/* output currently loaded configuration to file descriptor */
void config_print(int fd);

/* read and process a configuration file */
void config_read();

/* set a config key/value pair */
void config_set(char *key, void *val);

/* lookup type of config item */
config_type_t config_type(char *k);

#endif /* __LIBRECAST_CONFIG_H__ */
