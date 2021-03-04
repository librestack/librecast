#include "test.h"
#include <librecast/net.h>
#include "../src/librecast_pvt.h"
#include <signal.h>
#include <time.h>
#include <unistd.h>

static int gotmsg;

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
	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan;
	lc_message_t msg;
	int opt = 1;

	test_name("multicast ping (loopback)");

	lctx = lc_ctx_new();
	test_assert(lctx != NULL, "lctx != NULL");

	sock = lc_socket_new(lctx);
	test_assert(sock != NULL, "sock != NULL");

	chan = lc_channel_new(lctx, "example.com");
	test_assert(chan != NULL, "chan != NULL");

	test_assert(!lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &opt, sizeof(opt)),
			"set IPV6_MULTICAST_LOOP");

	test_assert(!lc_channel_bind(sock, chan), "lc_channel_bind()");
	test_assert(!lc_channel_join(chan), "lc_channel_join()");
	test_assert(!lc_socket_listen(sock, &msg_received, NULL), "lc_socket_listen()");

	/* send packet and receive on loopback */
	int op = LC_OP_PING;
	lc_msg_init(&msg);
	lc_msg_set(&msg, LC_ATTR_OPCODE, &op);
	signal(SIGINT, sighandler);
	ssize_t byt;
	byt = lc_msg_send(chan, &msg);
	test_assert(byt == msg.len + sizeof(lc_message_head_t), "%zi bytes sent", byt);
	if (byt == -1) {
		perror("lc_msg_send");
	}

	struct timespec t = { .tv_nsec = 99999999 };
	nanosleep(&t, &t);
	test_assert(gotmsg, "timeout waiting for loopback message");

	test_assert(!lc_socket_listen_cancel(sock), "lc_socket_listen_cancel()");
	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);

	return fails;
}
