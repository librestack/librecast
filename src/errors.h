#ifndef __LIBRECAST_ERRORS_H__
#define __LIBRECAST_ERRORS_H__ 1

#define ERROR_CODES(X)                                                        \
	X(0, ERROR_SUCCESS,             "Success")                            \
	X(1, ERROR_FAILURE,             "Failure")                            \
	X(2, ERROR_PID_OPEN,            "Failed to open pidfile")             \
	X(3, ERROR_PID_READFAIL,        "Failed to read pidfile")             \
	X(4, ERROR_PID_INVALID,         "Invalid pid")                        \
	X(5, ERROR_ALREADY_RUNNING,     "Daemon already running")             \
	X(6, ERROR_PID_WRITEFAIL,       "Failed to write to pidifile")

#define ERROR_MSG(code, name, msg) case code: return msg;
#define ERROR_ENUM(code, name, msg) name = code,
enum {
	ERROR_CODES(ERROR_ENUM)
};

/* return human readable error message for e */
char *error_msg(int e);

/* print human readable error, using errsv (errno) or progam defined (e) code */
void print_error(int e, int errsv, char *errstr);

#endif /* __LIBRECAST_ERRORS_H__ */
