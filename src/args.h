#ifndef __LIBRECAST_ARGS_H__
#define __LIBRECAST_ARGS_H__ 1

#define ARGS_ARGS(X) \
	X("start", "start the daemon", 0) \
	X("stop", "stop the daemon", 0) \
	X("status", "report status of daemon", 0)
#undef X

#define ARGS_ARG(name, desc, f) if (strcmp(arg, name) == 0) return 1;
#define ARGS_FUNC(name, desc, f) if (strcmp(arg, name) == 0) return f;

/* process all command line args and options */
int args_process(int argc, char **argv);

/* process single argument/option */
int args_process_arg(char *arg);

/* return true (1) if valid command-line argument */
int args_valid_arg(char *arg);

#endif /* __LIBRECAST_ARGS_H__ */
