#ifndef __LIBRECAST_SIGNALS_H__
#define __LIBRECAST_SIGNALS_H__ 1

#include <signal.h>

int sighandlers();
void sighup_handler (int signo);
void sigint_handler (int signo);
void sigterm_handler (int signo);
int signal_daemon (int signal, int lockfd);

#endif /* __LIBRECAST_SIGNALS_H__ */
