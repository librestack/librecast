#include <librecast.h>
#include <stdio.h>
#include <stdlib.h>

void print_msg(char *msg, ssize_t len)
{
	char *out = NULL;

	if (len > 0) {
		/* we cannot assume msg is null-terminated */
		out = calloc(1, len + 1);
		snprintf(out, len + 1, "%s", msg);
		puts(out);
		free(out);
	}
}

int main()
{
	lc_ctx_t *ctx = lc_ctx_new();
	lc_socket_t *sock;
	lc_channel_t *channel;
	ssize_t len = 0;
	char *msg = NULL;

	sock = lc_socket_new(ctx);
	channel = lc_channel_new(ctx, "librecast://chat.example.com/mychannel");
	lc_channel_bind(sock, channel);
	lc_channel_join(channel);

	len = lc_msg_recv(sock, &msg); /* blocking receiver */
	print_msg(msg, len);
	free(msg);

	lc_channel_leave(channel);
	lc_channel_free(channel);
	lc_socket_close(sock);
	lc_ctx_free(ctx);

	return 0;
}
