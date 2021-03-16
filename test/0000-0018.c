#include "test.h"
#include <librecast/net.h>
#include <librecast/net.h>
#include "../src/librecast_pvt.h"
#include <pthread.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#define WAITS 1

static char channame[][6] = { "red", "green", "blue" };
enum { channels = sizeof channame / sizeof channame[0] };
static sem_t sem;

void *recv_thread(void *arg)
{
	lc_ctx_t *lctx = lc_ctx_new();
	lc_socket_t *sock = lc_socket_new(lctx);
	test_assert(lctx != NULL, "lc_ctx_new() - recv thread");
	test_assert(sock != NULL, "lc_socket_new() - recv thread");
	lc_channel_t *chan[channels];
	char buf[BUFSIZ];

	for (int i = 0; i < channels; i++) {
		chan[i] = lc_channel_new(lctx, channame[i]);
		lc_channel_bind(sock, chan[i]);
		test_log("channel %s bound to socket %i", channame[i], chan[i]->sock->sock);
		lc_channel_join(chan[i]);
	}
	sem_post(&sem); /* ready */
	for (int i = 0; i < channels; i++) {
		lc_socket_recv(sock, buf, BUFSIZ, 0);
		sem_post(&sem);
	}
	lc_ctx_free(lctx);
	return arg;
}

int main(void)
{
	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan[channels];
	pthread_attr_t attr = {0};
	pthread_t thread;
	struct timespec ts;

	test_name("lc_socket_send()");

	lctx = lc_ctx_new();
	test_assert(lctx != NULL, "lc_ctx_new() - send thread");
	sock = lc_socket_new(lctx);
	test_assert(sock != NULL, "lc_socket_new() - send thread");

	lc_socket_loop(sock, 1);

	/* create some channels and bind to the same socket */
	for (int i = 0; i < channels; i++) {
		int rc;
		chan[i] = lc_channel_new(lctx, channame[i]);
		rc = lc_channel_bind(sock, chan[i]);
		test_assert(rc == 0, "lc_channel_bind() = %i", rc);
		perror("lc_channel_bind");
	}

	/* fire up receiver thread */
	sem_init(&sem, 0, 0);
	pthread_attr_init(&attr);
	pthread_create(&thread, &attr, &recv_thread, NULL);
	pthread_attr_destroy(&attr);
	sem_wait(&sem);

	/* send to all channels which are bound to this socket */
	lc_socket_send(sock, channame[0], strlen(channame[0]), 0);

	/* wait for recv thread */
	test_assert(!clock_gettime(CLOCK_REALTIME, &ts), "clock_gettime()");
	ts.tv_sec += WAITS;
	for (int i = 0; i < channels; i++) {
		/* ensure we received ALL channels */
		test_assert(!sem_timedwait(&sem, &ts), "timeout");
	}
	sem_destroy(&sem);

	pthread_cancel(thread);
	pthread_join(thread, NULL);

	lc_ctx_free(lctx);

	return fails;
}
