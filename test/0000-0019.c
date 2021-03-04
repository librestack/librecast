#include "test.h"
#include <librecast/net.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

void sighandler(int sig)
{
	/* do nothing => SIG_IGN ? */
}

void *testthread(void *arg)
{
	struct timespec ts = { 0, 200 };
	nanosleep(&ts, NULL);
	kill(getpid(), SIGINT);
	pthread_exit(arg);
}

int main()
{
	struct sigaction sa = { .sa_handler = sighandler };
	pthread_t thread;
	pthread_attr_t attr = {};
	char channame[] = "example.com";
	char data[] = "black lives matter";
	const int on = 1;
	ssize_t byt_sent;
	ssize_t byt_recv;

	test_name("lc_msg_send() / lc_msg_recv() - blocking network recv");

	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan;
	lc_message_t msg;
	int op;

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	chan = lc_channel_new(lctx, channame);

	/* set up signal handler so we can kill recv() */
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);

	/* fire up test thread */
	pthread_attr_init(&attr);

	/* talking to ourselves, set loopback */
	test_assert(!lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &on, sizeof(on)),
		"set IPV6_MULTICAST_LOOP");
	lc_channel_bind(sock, chan);
	lc_channel_join(chan);

	/* if we ping ourselves, will we go blind? */
	op = LC_OP_PING;
	lc_msg_init(&msg);
	lc_msg_set(&msg, LC_ATTR_OPCODE, &op);
	byt_sent = lc_msg_send(chan, &msg);
	lc_msg_free(&msg);			/* clear struct before recv */

	pthread_create(&thread, &attr, &testthread, NULL);
	byt_recv = lc_msg_recv(sock, &msg);	/* blocking recv */
	pthread_join(thread, NULL);

	test_log("sent %zi bytes", byt_sent);
	test_log("recv %zi bytes", byt_recv);
	test_assert(byt_sent == byt_recv, "bytes sent == bytes received (1)");
	test_assert(msg.op == op, "opcode matches");

	lc_msg_init_data(&msg, &data, strlen(data + 1), NULL, NULL);
	byt_sent = lc_msg_send(chan, &msg);
	lc_msg_init(&msg);

	pthread_create(&thread, &attr, testthread, NULL);
	errno = 0;
	byt_recv = lc_msg_recv(sock, &msg);	/* blocking recv */
	pthread_cancel(thread);
	pthread_join(thread, NULL);

	test_assert(errno != EINTR, "lc_msg_recv EINTR");
	test_log("sent %zi bytes", byt_sent);
	test_log("recv %zi bytes", byt_recv);
	test_assert(byt_sent == byt_recv, "bytes sent == bytes received (2)");
	test_expectn(data, msg.data, msg.len); /* got our data back */

	lc_msg_free(&msg);

	pthread_attr_destroy(&attr);

	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);

	return fails;
}
