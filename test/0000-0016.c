#include "test.h"
#include <librecast/net.h>
#include <pthread.h>
#include <semaphore.h>

static char channel_name[] = "0000-0016";
static sem_t sem;
static ssize_t bytes = -1;

static void *listen_thread(void *arg)
{
	lc_ctx_t * lctx;
	lc_socket_t * sock;
	lc_channel_t * chan;
	struct iovec iov;
	struct msghdr msg = {0};

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	chan = lc_channel_new(lctx, channel_name);

	iov.iov_base = arg;
	iov.iov_len = BUFSIZ;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	lc_channel_bind(sock, chan);
	lc_channel_join(chan);

	sem_post(&sem); /* tell send thread we're ready */
	bytes = lc_socket_recvmsg(sock, &msg, 0);

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
	char buf[] = "liberté";
	char recvbuf[BUFSIZ] = "";
	struct iovec iov;
	struct msghdr msg = {0};

	test_name("lc_channel_sendmsg() / lc_socket_recvmsg()");

	sem_init(&sem, 0, 0);

	pthread_attr_init(&attr);
	pthread_create(&thread, &attr, &listen_thread, &recvbuf);
	pthread_attr_destroy(&attr);

	sem_wait(&sem); sem_destroy(&sem); /* recv thread is ready */

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	chan = lc_channel_new(lctx, channel_name);

	iov.iov_base = buf;
	iov.iov_len = strlen(buf) + 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	lc_socket_loop(sock, 1);
	lc_channel_bind(sock, chan);
	lc_channel_sendmsg(chan, &msg, 0);
	lc_ctx_free(lctx);

	pthread_join(thread, NULL);

	test_assert(bytes == (ssize_t)iov.iov_len,
			"received %zi bytes, expected %zu", bytes, iov.iov_len);
	test_expect(buf, recvbuf);

	return fails;
}
