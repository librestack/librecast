#ifndef __LIBRECAST_SIGNALS_H__
#define __LIBRECAST_SIGNALS_H__ 1

int sighandlers();
void sighup_handler (int signo);
void sigint_handler (int signo);
void sigterm_handler (int signo);

#endif /* __LIBRECAST_SIGNALS_H__ */
