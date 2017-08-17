#ifndef __LIBRECAST_ERRORS_H__
#define __LIBRECAST_ERRORS_H__ 1

#include <errno.h>

#define LC_ERROR_CODES(X)                                                        \
	X(0, LC_ERROR_SUCCESS,             "Success")                            \
	X(1, LC_ERROR_FAILURE,             "Failure")                            \
	X(2, LC_ERROR_PID_OPEN,            "Failed to open pidfile")             \
	X(3, LC_ERROR_PID_READFAIL,        "Failed to read pidfile")             \
	X(4, LC_ERROR_PID_INVALID,         "Invalid pid")                        \
	X(5, LC_ERROR_ALREADY_RUNNING,     "Daemon already running")             \
	X(6, LC_ERROR_PID_WRITEFAIL,       "Failed to write to pidfile")         \
	X(7, LC_ERROR_DAEMON_FAILURE,      "Failed to daemonize")                \
	X(8, LC_ERROR_CONFIG_NOTNUMERIC,   "Numeric config value not numeric")   \
	X(9, LC_ERROR_CONFIG_BOUNDS,       "Numeric config value out of bounds") \
	X(10, LC_ERROR_CONFIG_BOOLEAN,     "Invalid boolean config value")       \
	X(11, LC_ERROR_CONFIG_READFAIL,    "Unable to read config file")         \
	X(12, LC_ERROR_CONFIG_INVALID,     "Error in config file")               \
	X(13, LC_ERROR_MALLOC,             "Memory allocation error")            \
	X(14, LC_ERROR_INVALID_ARGS,       "Invalid command line options")       \
	X(15, LC_ERROR_DAEMON_STOPPED,     "Daemon not running")                 \
	X(16, LC_ERROR_NET_SEND,           "Error sending data")                 \
	X(17, LC_ERROR_NET_RECV,           "Error receiving data")               \
	X(18, LC_ERROR_NET_SOCKOPT,        "Error setting socket options")       \
	X(19, LC_ERROR_CMD_INVALID,        "Invalid Command received")           \
	X(20, LC_ERROR_SOCKET_CREATE,      "Unable to create unix socket")       \
	X(21, LC_ERROR_SOCKET_CONNECT,     "Unable to connect to unix socket")   \
	X(22, LC_ERROR_SOCKET_BIND,        "Unable to bind to unix socket")      \
	X(23, LC_ERROR_MCAST_JOIN,         "Multicast join failed")              \
	X(24, LC_ERROR_MCAST_LEAVE,        "Multicast leave failed")             \
	X(25, LC_ERROR_SOCKET_LISTENING,   "Socket already listening")
#undef X

#define LC_ERROR_MSG(code, name, msg) case code: return msg;
#define LC_ERROR_ENUM(code, name, msg) name = code,
enum {
	LC_ERROR_CODES(LC_ERROR_ENUM)
};

/* log message and return code */
int lc_error_log(int level, int e);

/* return human readable error message for e */
char *lc_error_msg(int e);

/* print human readable error, using errsv (errno) or progam defined (e) code */
void lc_print_error(int e, int errsv, char *errstr);

#endif /* __LIBRECAST_ERRORS_H__ */
