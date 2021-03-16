#include "test.h"
#include <librecast/net.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#define WAITS 1

static sem_t sem;
static ssize_t byt_recv, byt_sent;
static char channame[] = "0000-0019";
static char data[] = "black lives matter";

void *testthread(void *arg)
{
	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan;
	lc_message_t msg;
	char buf[BUFSIZ];

	lc_msg_init(&msg);
	msg.data = buf;
	msg.len = BUFSIZ;

	lctx = lc_ctx_new();
	test_assert(lctx != NULL, "lc_ctx_new()");
	sock = lc_socket_new(lctx);
	test_assert(sock != NULL, "lc_socket_new()");
	chan = lc_channel_new(lctx, channame);
	test_assert(chan != NULL, "lc_channel_new()");

	test_assert(lc_channel_bind(sock, chan) == 0, "lc_channel_bind()");
	test_assert(lc_channel_join(chan) == 0, "lc_channel_join()");

	sem_post(&sem); /* tell send thread we're ready */
	byt_recv = lc_msg_recv(sock, &msg);

	test_log("sent %zi bytes", byt_sent);
	test_log("recv %zi bytes", byt_recv);

	test_assert(msg.op == LC_OP_PING, "opcode matches");
	test_assert(byt_sent == byt_recv, "bytes sent (%zi) == bytes received (%zi)",
			byt_sent, byt_recv);
	test_expectn(data, msg.data, msg.len); /* got our data back */

	sem_post(&sem); /* tell send thread we're done */

	return arg;
}

int main()
{
	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan;
	lc_message_t msg;
	pthread_attr_t attr;
	pthread_t thread;
	struct timespec ts;
	unsigned op;

	test_name("lc_msg_send() / lc_msg_recv() - blocking network recv");

	/* fire up test thread */
	sem_init(&sem, 0, 0);
	pthread_attr_init(&attr);
	pthread_create(&thread, &attr, &testthread, NULL);
	pthread_attr_destroy(&attr);
	sem_wait(&sem); /* recv thread is ready */

	/* Librecast Context, Socket + Channel */
	lctx = lc_ctx_new();
	test_assert(lctx != NULL, "lc_ctx_new()");
	sock = lc_socket_new(lctx);
	test_assert(sock != NULL, "lc_socket_new()");
	chan = lc_channel_new(lctx, channame);
	test_assert(chan != NULL, "lc_channel_new()");
	lc_socket_loop(sock, 1); /* talking to ourselves, set loopback */
	lc_channel_bind(sock, chan);

	/* send msg with PING opcode */
	op = LC_OP_PING;
	lc_msg_init_data(&msg, &data, strlen(data + 1), NULL, NULL);
	lc_msg_set(&msg, LC_ATTR_OPCODE, &op);
	byt_sent = lc_msg_send(chan, &msg);
	lc_msg_free(&msg); /* clear struct before recv */

	/* wait for recv thread */
	test_assert(!clock_gettime(CLOCK_REALTIME, &ts), "clock_gettime()");
	ts.tv_sec += WAITS;
	test_assert(!sem_timedwait(&sem, &ts), "timeout");
	sem_destroy(&sem);

	/* clean up */
	pthread_cancel(thread);
	pthread_join(thread, NULL);
	lc_msg_free(&msg);
	lc_ctx_free(lctx);

	return fails;
}
