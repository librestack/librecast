#include <librecast.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main()
{
	lc_ctx_t *ctx = lc_ctx_new();
	lc_socket_t *sock;
	lc_channel_t *channel;
	char msg[] = "Hello, multicast world!";

	sock = lc_socket_new(ctx);
	channel = lc_channel_new(ctx, "librecast://chat.example.com/mychannel");

	lc_channel_bind(sock, channel);

	/* NB: there is no need to join a channel to send to it */

	lc_msg_send(channel, msg, strlen(msg));

	lc_channel_free(channel);
	lc_socket_close(sock);
	lc_ctx_free(ctx);

	return 0;
}
