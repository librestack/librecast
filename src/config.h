#ifndef __LIBRECAST_CONFIG_H__
#define __LIBRECAST_CONFIG_H__ 1

#define CONFIG_DEFAULTS \
	X("daemon", "0", "run as daemon") \
	X("dropprivs", "1", "drop root privileges")
#undef X

void config_defaults();
void * config_get(char *key);
void config_set(char *key, void *val);
void free_config();

#endif /* __LIBRECAST_CONFIG_H__ */
