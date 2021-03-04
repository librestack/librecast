#include "test.h"
#include <librecast/net.h>
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
	kill(getpid(), SIGINT);
}

int main()
{
	lc_ctx_t *lctx = NULL;
	lc_socket_t *sock[2] = { NULL, NULL };
	lc_channel_t *chan[2] = { NULL, NULL };
	lc_message_t msg;

	test_name("multicast ping (loopback) - don't receive msgs for other channels");

	lctx = lc_ctx_new();
	sock[0] = lc_socket_new(lctx);
	sock[1] = lc_socket_new(lctx);
	chan[0] = lc_channel_new(lctx, "chan0");
	chan[1] = lc_channel_new(lctx, "chan1");

	test_assert(!lc_channel_bind(sock[0], chan[0]), "lc_channel_bind() 0");
	test_assert(!lc_channel_bind(sock[1], chan[1]), "lc_channel_bind() 1");
	test_assert(!lc_channel_join(chan[0]), "lc_channel_join() 0");
	/* do NOT join channel 1 */
	test_assert(!lc_socket_listen(sock[0], msg_received, NULL), "lc_socket_listen() 0");
	test_assert(!lc_socket_listen(sock[1], msg_received, NULL), "lc_socket_listen() 1");

	/* send packet and receive on loopback */
	int op = LC_OP_PING;
	lc_msg_init(&msg);
	lc_msg_set(&msg, LC_ATTR_OPCODE, &op);
	signal(SIGINT, sighandler);
	lc_msg_send(chan[1], &msg); /* send to channel we are NOT joined to */

	struct timespec t;
	t.tv_sec = 0;
	t.tv_nsec = 99999999;
	nanosleep(&t, &t);
	/* fail if message for wrong channel was received */
	test_assert(!gotmsg, "received loopback message on channel not joined");

	test_assert(!lc_socket_listen_cancel(sock[0]), "lc_socket_listen_cancel()");
	test_assert(!lc_socket_listen_cancel(sock[1]), "lc_socket_listen_cancel()");
	lc_channel_free(chan[0]);
	lc_channel_free(chan[1]);
	lc_socket_close(sock[0]);
	lc_socket_close(sock[1]);
	lc_ctx_free(lctx);

	return fails;
}
