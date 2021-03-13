#include "test.h"
#include <librecast/net.h>
#include <pthread.h>
#include <semaphore.h>

#define WAITS 1

static char channel_name[] = "0000-0015";
static sem_t sem;
static ssize_t bytes = -1;

static void *listen_thread(void *arg)
{
	lc_ctx_t * lctx;
	lc_socket_t * sock;
	lc_channel_t * chan;

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	chan = lc_channel_new(lctx, channel_name);

	lc_channel_bind(sock, chan);
	lc_channel_join(chan);

	sem_post(&sem); /* tell send thread we're ready */
	bytes = lc_socket_recv(sock, (char *)arg, BUFSIZ, 0);
	sem_post(&sem); /* tell send thread we're done */

	lc_ctx_free(lctx);
	return arg;
}

int main(void)
{
	lc_ctx_t * lctx;
	lc_socket_t * sock;
	lc_channel_t * chan;
	pthread_attr_t attr = {0};
	pthread_t thread;
	struct timespec ts;
	char buf[] = "liberté";
	char recvbuf[BUFSIZ] = "";
	size_t len = strlen(buf) + 1;

	test_name("lc_channel_send() / lc_socket_recv()");

	sem_init(&sem, 0, 0);

	pthread_attr_init(&attr);
	pthread_create(&thread, &attr, &listen_thread, &recvbuf);
	pthread_attr_destroy(&attr);

	sem_wait(&sem); /* recv thread is ready */

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	chan = lc_channel_new(lctx, channel_name);

	lc_socket_loop(sock, 1);
	lc_channel_bind(sock, chan);
	lc_channel_send(chan, buf, len, 0);
	lc_ctx_free(lctx);

	test_assert(!clock_gettime(CLOCK_REALTIME, &ts), "clock_gettime()");
	ts.tv_sec += WAITS;
	test_assert(!sem_timedwait(&sem, &ts), "timeout");
	sem_timedwait(&sem, &ts);
	sem_destroy(&sem);

	pthread_cancel(thread);
	pthread_join(thread, NULL);

	test_assert(bytes == (ssize_t)len, "received %zi bytes, expected %zu", bytes, len);
	test_expect(buf, recvbuf);

	return fails;
}
