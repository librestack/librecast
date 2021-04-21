/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2017-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef __LIBRECAST_ERRORS_H__
#define __LIBRECAST_ERRORS_H__ 1

#include <errno.h>

#define LC_ERROR_CODES(X)                                                        \
	X(0, LC_ERROR_SUCCESS,             "Success")                            \
	X(-1, LC_ERROR_FAILURE,             "Failure")                            \
	X(-2, LC_ERROR_PID_OPEN,            "Failed to open pidfile")             \
	X(-3, LC_ERROR_PID_READFAIL,        "Failed to read pidfile")             \
	X(-4, LC_ERROR_PID_INVALID,         "Invalid pid")                        \
	X(-5, LC_ERROR_ALREADY_RUNNING,     "Daemon already running")             \
	X(-6, LC_ERROR_PID_WRITEFAIL,       "Failed to write to pidfile")         \
	X(-7, LC_ERROR_DAEMON_FAILURE,      "Failed to daemonize")                \
	X(-8, LC_ERROR_CONFIG_NOTNUMERIC,   "Numeric config value not numeric")   \
	X(-9, LC_ERROR_CONFIG_BOUNDS,       "Numeric config value out of bounds") \
	X(-10, LC_ERROR_CONFIG_BOOLEAN,     "Invalid boolean config value")       \
	X(-11, LC_ERROR_CONFIG_READFAIL,    "Unable to read config file")         \
	X(-12, LC_ERROR_CONFIG_INVALID,     "Error in config file")               \
	X(-13, LC_ERROR_MALLOC,             "Memory allocation error")            \
	X(-14, LC_ERROR_INVALID_ARGS,       "Invalid command line options")       \
	X(-15, LC_ERROR_DAEMON_STOPPED,     "Daemon not running")                 \
	X(-16, LC_ERROR_NET_SEND,           "Error sending data")                 \
	X(-17, LC_ERROR_NET_RECV,           "Error receiving data")               \
	X(-18, LC_ERROR_NET_SOCKOPT,        "Error setting socket options")       \
	X(-19, LC_ERROR_CMD_INVALID,        "Invalid Command received")           \
	X(-20, LC_ERROR_SOCKET_CREATE,      "Unable to create unix socket")       \
	X(-21, LC_ERROR_SOCKET_CONNECT,     "Unable to connect to unix socket")   \
	X(-22, LC_ERROR_SOCKET_BIND,        "Unable to bind to unix socket")      \
	X(-23, LC_ERROR_MCAST_JOIN,         "Multicast join failed")              \
	X(-24, LC_ERROR_MCAST_PART,         "Multicast part failed")              \
	X(-25, LC_ERROR_SOCKET_LISTENING,   "Socket already listening")           \
	X(-26, LC_ERROR_BRIDGE_INIT,        "Unable to setup bridge control")     \
	X(-27, LC_ERROR_BRIDGE_EXISTS,      "Bridge already exists")              \
	X(-28, LC_ERROR_BRIDGE_ADD_FAIL,    "Bridge creation failed")             \
	X(-29, LC_ERROR_TAP_ADD_FAIL,       "TAP creation failed")                \
	X(-30, LC_ERROR_BRIDGE_NODEV,       "Bridge does not exist")              \
	X(-31, LC_ERROR_IF_NODEV,           "Interface does not exist")           \
	X(-32, LC_ERROR_IF_BUSY,            "Interface already bridged")          \
	X(-33, LC_ERROR_IF_LOOP,            "Interface is a bridge")              \
	X(-34, LC_ERROR_IF_OPNOTSUPP,       "Interface does not support bridging") \
	X(-35, LC_ERROR_IF_BRIDGE_FAIL,     "Unable to bridge interface")         \
	X(-36, LC_ERROR_SOCK_IOCTL,         "Unable to create ioctl socket")      \
	X(-37, LC_ERROR_IF_UP_FAIL,         "Unable to bring up interface")       \
	X(-38, LC_ERROR_CTX_REQUIRED,       "Librecast context required for this operation") \
	X(-39, LC_ERROR_INVALID_BASEADDR,   "Invalid hashgroup baseaddr") \
	X(-40, LC_ERROR_RANDOM_OPEN,        "Unable to open random source") \
	X(-41, LC_ERROR_RANDOM_READ,        "Unable to read random source") \
	X(-42, LC_ERROR_HASH_INIT,          "Unable to initialize hash") \
	X(-43, LC_ERROR_HASH_UPDATE,        "Unable to hash data") \
	X(-44, LC_ERROR_HASH_FINAL,         "Unable to finalize hash") \
	X(-45, LC_ERROR_DB_OPEN,            "Unable to open database") \
	X(-46, LC_ERROR_DB_EXEC,            "Error executing database operation") \
	X(-47, LC_ERROR_DB_REQUIRED,        "Database required") \
	X(-48, LC_ERROR_DB_KEYNOTFOUND,     "Requested key not found in database") \
	X(-49, LC_ERROR_SOCKET_REQUIRED,    "Librecast socket required for this operation") \
	X(-50, LC_ERROR_CHANNEL_REQUIRED,   "Librecast channel required for this operation") \
	X(-51, LC_ERROR_MESSAGE_REQUIRED,   "Librecast message required for this operation") \
	X(-52, LC_ERROR_MESSAGE_EMPTY,      "message has no payload") \
	X(-53, LC_ERROR_INVALID_PARAMS,     "Invalid arguments to function") \
	X(-54, LC_ERROR_MSG_ATTR_UNKNOWN,   "Unknown message attribute") \
	X(-55, LC_ERROR_THREAD_CANCEL,      "Failed to cancel thread") \
	X(-56, LC_ERROR_THREAD_JOIN,        "Failed to join thread") \
	X(-57, LC_ERROR_INVALID_OPCODE,     "Invalid opcode") \
	X(-58, LC_ERROR_QUERY_REQUIRED,     "Librecast query required for this operation") \
	X(-59, LC_ERROR_SETSOCKOPT,         "Unable to set socket option")
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
