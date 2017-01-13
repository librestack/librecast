#include <ncurses.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "commands.h"
#include "config.h"
#include "errors.h"
#include "net.h"
#include "nodewatch.h"
#include "socket.h"

#define PROGRAM "librecast"
#define COL_NODE 0
#define COL_IP 10
#define COL_SEEN 50
#define COL_STRATUM 70
#define COL_BRIDGE 80

node_t *nodes = NULL;

void handle_winch(int sig)
{
	endwin();
	refresh();
	clear();
}

void update_node(char *name, char *ip, int stratum, char *bridge)
{
	node_t *n, *new, *p;

	n = nodes;
	while (n != NULL) {
		if (strcmp(ip, n->ip) == 0) {
			/* matching node, update */
			n->seen = time(NULL);
			return;
		}
		p = n;
		n = n->next;
	}

	new = calloc(1, sizeof(node_t));
	new->name = strdup(name);
	new->ip = strdup(ip);
	new->seen = time(NULL);
	new->stratum = stratum;
	new->bridge = strdup(bridge);

	if (nodes == NULL)
		nodes = new;
	else
		p->next = new;
}

int initialize()
{
	int e = 0;

	signal(SIGWINCH, handle_winch);
	initscr();
	noecho();
	curs_set(0);
	keypad(stdscr, TRUE);
	config_defaults();
	config_set_num("loglevel", 0);
	while ((e = socket_bind()) != 0) {
		if (e != ERROR_SOCKET_CONNECT)
			return e;
		clear();
		printw("%s", error_msg(e));
		refresh();
		halfdelay(10);
		getch();
	}
	halfdelay(1);

	return 0;
}

void cleanup()
{
	node_t *n, *p;

	socket_close();
	n = nodes;
	while (n != NULL) {
		free(n->name);
		free(n->ip);
		free(n->bridge);
		p = n;
		n = n->next;
		free(p);
	}
	endwin();
}

node_t *get_node(char *node)
{
	node_t *n;

	n = nodes;
	while (n != NULL) {
		if (strcmp(node, n->name) == 0) {
			return n;
		}
		n = n->next;
	}
	return NULL;
}

void display_header(int rows, int cols)
{
	while (cols-- > 0) {
		mvprintw(1, cols, "-");
	}
	attron(A_BOLD | A_UNDERLINE);
	mvprintw(2, COL_NODE, "node");
	mvprintw(2, COL_IP, "ip");
	mvprintw(2, COL_SEEN, "last seen");
	mvprintw(2, COL_STRATUM, "stratum");
	mvprintw(2, COL_BRIDGE, "bridge");
	attroff(A_BOLD | A_UNDERLINE);
}

void display_nodes()
{
	int y = 3;
	node_t *n;
	struct tm *tm_info;
	char buf[26];

	n = nodes;
	while (n != NULL) {
		tm_info = localtime(&n->seen);
		strftime(buf, 26, "%Y-%m-%d %H:%M:%S", tm_info);
		mvprintw(y, COL_NODE, "%s", n->name);
		mvprintw(y, COL_IP, "%s", n->ip);
		mvprintw(y, COL_SEEN, "%s", buf);
		mvprintw(y, COL_STRATUM+3, "%i", n->stratum);
		mvprintw(y++, COL_BRIDGE, "%s", n->bridge);
		n = n->next;
	}
}

void display_time()
{
	time_t now;
	time(&now);
	mvprintw(0, 0, "%s - %s", PROGRAM, asctime(localtime((&now))));
	refresh();
}

void read_socket()
{
	char buf[1024];
	int bytes;

	bytes = socket_read(buf);
	if (bytes > 0) {
		buf[bytes] = '\0';
		update_node("-", buf, 0, "-");
	}

}

void update()
{
	int rows, cols;
	read_socket();
	getmaxyx(stdscr, rows, cols);
	display_time();
	display_header(rows, cols);
	display_nodes();
}

void main_free()
{
	config_free();
}

int main()
{
	int e = 0;

	if ((e = initialize()) == 0) {
		do {
			update();
		} while (strcmp(keyname(getch()), "^c") != 0);
		cleanup();
	}

	return e;
}
