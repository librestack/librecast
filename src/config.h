#ifndef __LIBRECAST_CONFIG_H__
#define __LIBRECAST_CONFIG_H__ 1

#define CONFIG_DEFAULTS \
	X("configfile", "/etc/librecast.conf", "path to config file") \
	X("daemon", "0", "run as daemon") \
	X("dropprivs", "1", "drop root privileges")
#undef X

/* set configuration defaults, before overriding with any options or reading
 * a configuration file */
void config_defaults();

/* free config memory */
void config_free();

/* get a config value by name */
void * config_get(char *key);

/* output currently loaded configuration */
void config_print();

/* read and process a configuration file */
void config_read();

/* set a config key/value pair */
void config_set(char *key, void *val);

#endif /* __LIBRECAST_CONFIG_H__ */
