#define _GNU_SOURCE
#include <curses.h>
#include <librecast.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFSIZE 1024
#define MAX_USERNAME 32
#define NICK_DEFAULT "nobody"

#define TIDS 1
pthread_t tid[TIDS];
char *nick;
lc_ctx_t *ctx;
lc_socket_t *sock;
lc_channel_t *channel;

void *await_input();
void *await_data();
void cleanup();
void display_data(char *data, size_t len);
void channel_join(char *channame);
void process_input(char *input);
void screen_init();
void sig_handler(int signo);

void *await_input()
{
	char buf[BUFSIZE];

	printw("%s> ", nick);
	while (1) {
		getnstr(buf, BUFSIZE);
		process_input(buf);
		refresh();
	}
	return NULL;
}

void *await_data()
{
	ssize_t len = 0;
	char *msg;
	while (1) {
		len = lc_msg_recv(sock, &msg);
		if (len > 0)
			display_data(msg, len);
		free(msg);
	}
	return NULL;
}

void cleanup()
{
	endwin();
	free(nick);
	lc_channel_free(channel);
	lc_socket_close(sock);
	lc_ctx_free(ctx);
}

void channel_join(char *channame)
{
	/* TODO
	 * new ncurses win for channel
	 * join mcast channel
	 */
	channel = lc_channel_new(ctx, channame);
	lc_channel_bind(sock, channel);
	lc_channel_join(channel);
}

void display_data(char *data, size_t len)
{
	char *out = NULL;
	int x, y;
	out = calloc(1, BUFSIZE + 1);
	getyx(stdscr, y, x);
	move(y, 0);
	clrtoeol();
	snprintf(out, len + 1, "%s\n\n", data);
	scrl(1);
	printw(out);
	getyx(stdscr, y, x);
	mvprintw(y + 1, x - x, "%s> ", nick);
	refresh();
	free(out);
}

void process_input(char *input)
{
	char *data;
	asprintf(&data, "<%s> %s", nick, input);
	lc_msg_send(channel, data, strlen(data));
	free(data);
}

void screen_init()
{
	signal(SIGINT, sig_handler);
	signal(SIGWINCH, sig_handler);
	initscr();
}

void sig_handler(int signo)
{
        switch (signo) {
        case SIGINT:
		cleanup();
                _exit(0);
        case SIGWINCH:
                endwin();
                refresh();
                clear();
                break;
        default:
                break;
        }
}

int main()
{
	nick = calloc(1, MAX_USERNAME + 1);
	ctx = lc_ctx_new();
	sock = lc_socket_new(ctx);
	pthread_attr_t attr = {};

	if (getlogin_r(nick, MAX_USERNAME + 1) != 0) {
		nick = strdup(NICK_DEFAULT);
	}

	screen_init();
	channel_join("librecast://chat.example.com/mychannel");
	pthread_create(&(tid[0]), &attr, &await_data, NULL);
	await_input();

	/* not reached */

	return 0;
}
