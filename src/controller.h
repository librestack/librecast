#ifndef __LIBRECAST_CONTROLLER_H__
#define __LIBRECAST_CONTROLLER_H__ 1

#define CONTROLLER_THREADS(X) \
	X(0, CONTROLLER_THREAD_LISTENER, "receiver", net_multicast_listen) \
	X(1, CONTROLLER_THREAD_PING, "ping", controller_ping)
#undef X

#define CONTROLLER_THREADS_START(id, name, desc, f) pthread_create(&(tid[id]), &attr, &f, NULL);
#define CONTROLLER_THREADS_CANCEL(id, name, desc, f) pthread_cancel((tid[id]));
#define CONTROLLER_THREADS_JOIN(id, name, desc, f) pthread_join(tid[id], NULL);
#define CONTROLLER_THREADS_JOIN_EX(id, name, desc, f) controller_thread_join(id, desc);
#define CONTROLLER_THREADS_SIGINT(id, name, desc, f) pthread_kill(tid[id], SIGINT);
#define CONTROLLER_THREADS_F(id, name, desc, f) case id: return f;
#define CONTROLLER_THREADS_ENUM(id, name, desc, f) name = id,
enum {
	CONTROLLER_THREADS(CONTROLLER_THREADS_ENUM)
};

void controller_join_all();
void *controller_ping();
void controller_reload();
void controller_shutdown();
void controller_start(int lockfd);
void controller_thread_join(int id, char *desc);

#endif /* __LIBRECAST_CONTROLLER_H__ */
