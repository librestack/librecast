#include "test.h"
#include <librecast/net.h>
#include "../src/log.h"
#include <signal.h>
#include <time.h>
#include <unistd.h>

int gotmsg = 0;

void sighandler(int sig)
{
	test_log("caught signal");
}

void msg_received(lc_message_t *msg)
{
	test_log("message received");
	gotmsg = 1;
	kill(getpid(), SIGINT); /* FIXME: valgrind interfering with signal */
}

int main()
{
	test_name("multicast ping (loopback)");
	LOG_LEVEL = 127;
	lc_ctx_t *lctx = NULL;
	lc_socket_t *sock = NULL; 
	lc_channel_t *chan = NULL;
	lc_message_t msg;
	int opt = 1;

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	chan = lc_channel_new(lctx, "example.com");

	test_assert(!lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &opt, sizeof(opt)),
			"set IPV6_MULTICAST_LOOP");

	test_assert(!lc_channel_bind(sock, chan), "lc_channel_bind()");
	test_assert(!lc_channel_join(chan), "lc_channel_join()");
	test_assert(!lc_socket_listen(sock, msg_received, NULL), "lc_socket_listen()");

	/* send packet and receive on loopback */
	int op = LC_OP_PING;
	lc_msg_init(&msg);
	lc_msg_set(&msg, LC_ATTR_OPCODE, &op);
	signal(SIGINT, sighandler);
	lc_msg_send(chan, &msg);

	struct timespec t;
	t.tv_sec = 0;
	t.tv_nsec = 99999999;
	nanosleep(&t, &t);
	test_assert(gotmsg, "timeout waiting for loopback message");

	test_assert(!lc_socket_listen_cancel(sock), "lc_socket_listen_cancel()");
	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);

	return fails;
}
