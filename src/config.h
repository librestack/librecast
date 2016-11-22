#ifndef __LIBRECAST_CONFIG_H__
#define __LIBRECAST_CONFIG_H__ 1

void * config_get(char *key);
void config_set(char *key, void *val);
void free_config();

#endif /* __LIBRECAST_CONFIG_H__ */
