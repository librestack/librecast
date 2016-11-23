#ifndef __LIBRECAST_PID_H__
#define __LIBRECAST_PID_H__ 1

/* return full path of program lockfile. free() after use. */
char *getlockfilename();

/* get a lock and write pid */
int obtain_lockfile();

#endif /* __LIBRECAST_PID_H__ */
