#ifndef __LIBRECAST_ERRORS_H__
#define __LIBRECAST_ERRORS_H__ 1

#define ERROR_CODES(X)                                                         \
	X(0, ERROR_SUCCESS,     "Success")                                     \
	X(1, ERROR_FAIL,        "Failure")

#define ERROR_MSG(code, name, msg) case code: return msg;
#define ERROR_ENUM(code, name, msg) name = code,
enum {
	ERROR_CODES(ERROR_ENUM)
};

/* print human readable error, using errsv (errno) or progam defined (e) code */
void print_error(int e, int errsv, char *errstr);

#endif /* __LIBRECAST_ERRORS_H__ */
