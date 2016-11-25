#ifndef __LIBRECAST_COMMANDS_H__
#define __LIBRECAST_COMMANDS_H__ 1

#define COMMAND_CODES(X) \
	X(0,    CMD_NOOP,       "NOOP",         "Do nothing", command_noop) \
	X(1,    CMD_RELOAD,     "RELOAD",       "Reload configuration", command_reload) \
	X(2,    CMD_STOP,       "STOP",         "Stop daemon", command_stop) \
	X(4,    CMD_PING,       "ECHO",         "Echo request", command_ping) \
	X(8,    CMD_TIME,       "TIME",         "Request time", command_time)
#undef X

#define COMMAND_FUNC(code, name, cmd, desc, f) case code: return f;
#define COMMAND_CMD(code, name, cmd, desc, f) case code: return cmd;
#define COMMAND_DESC(code, name, cmd, desc, f) case code: return desc;
#define COMMAND_CODES_ENUM(code, name, cmd, desc, f) name = code,
enum {
	        COMMAND_CODES(COMMAND_CODES_ENUM)
};

int command_noop();
int command_reload();
int command_stop();
int command_ping();
int command_time();

#endif /* __LIBRECAST_COMMANDS_H__ */
