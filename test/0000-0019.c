#include "test.h"
#include <librecast/net.h>
#include "../src/errors.h"
#include "../src/log.h"
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
	test_name("lc_msg_send() / lc_msg_recv() - blocking network recv");
	LOG_LEVEL = 127;

	char channame[] = "example.com";
	char data[] = "black lives matter";
	const int on = 1;
	ssize_t byt_sent;
	ssize_t byt_recv;
	lc_ctx_t *lctx = lc_ctx_new();
	lc_socket_t *sock = lc_socket_new(lctx);
	lc_channel_t *chan = lc_channel_new(lctx, channame);
	lc_message_t msg;

	/* talking to ourselves, set loopback */
	test_assert(!lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &on, sizeof(on)),
		"set IPV6_MULTICAST_LOOP");
	lc_channel_bind(sock, chan);
	lc_channel_join(chan);

	/* if we ping ourselves, will we go blind? */
	int op = LC_OP_PING;
	lc_msg_init(&msg);
	lc_msg_set(&msg, LC_ATTR_OPCODE, &op);
	byt_sent = lc_msg_send(chan, &msg);
	lc_msg_free(&msg);			/* clear struct before recv */
	byt_recv = lc_msg_recv(sock, &msg);	/* blocking recv */
	test_log("sent %zi bytes", byt_sent);
	test_log("recv %zi bytes", byt_recv);
	test_assert(byt_sent == byt_recv, "bytes sent == bytes received (1)");
	test_assert(msg.op == op, "opcode matches");

	lc_msg_init_data(&msg, &data, strlen(data + 1), NULL, NULL);
	byt_sent = lc_msg_send(chan, &msg);
	lc_msg_init(&msg);
	byt_recv = lc_msg_recv(sock, &msg);	/* blocking recv */
	test_log("sent %zi bytes", byt_sent);
	test_log("recv %zi bytes", byt_recv);
	test_assert(byt_sent == byt_recv, "bytes sent == bytes received (2)");
	test_expectn(data, msg.data, msg.len); /* got our data back */
	lc_msg_free(&msg);
	
	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);

	return fails;
}
