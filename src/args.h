#ifndef __LIBRECAST_ARGS_H__
#define __LIBRECAST_ARGS_H__ 1

#include <signal.h>

#define ARGS_ARGS(X) \
	X("stop", "stop the daemon", SIGINT) \
	X("reload", "reload daemon configuration", SIGHUP) \
	X("status", "report status of daemon", 0) \
	X("cmd", "send command to daemon", 0)
#undef X

#define ARGS_ARG(name, desc, signal) if (strcmp(arg, name) == 0) return 1;
#define ARGS_SIGNAL(name, desc, signal) if (strcmp(arg, name) == 0) return signal;

/* process all command line args and options */
int args_process(int argc, char **argv);

/* process single argument/option */
int args_process_arg(char *arg);

/* return associated signal, or 0 */
int args_signal(char *arg);

/* return true (1) if valid command-line argument */
int args_valid_arg(char *arg);

#endif /* __LIBRECAST_ARGS_H__ */
