#include "test.h"
#include <librecast/net.h>
#include <librecast/if.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define WAITS 1
#define IF_COUNT 3

char hail[IF_COUNT][11] = {
	"Liberté",
	"Egalité",
	"Fraternité",
};
char recvbuf[IF_COUNT][BUFSIZ] = {0};
static char channel_name[] = "0000-0017";
static char ifname[IF_COUNT][IFNAMSIZ];
static sem_t sem_ready;
static sem_t sem_done;
static ssize_t bytes = -1;

static void *recv_thread(void *arg)
{
	int dir = *(int *)arg;
	lc_ctx_t * lctx;
	lc_socket_t * sock;
	lc_channel_t * chan;

	test_log("thread %i", dir);

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	chan = lc_channel_new(lctx, channel_name);

	test_assert(lc_socket_bind(sock, if_nametoindex(ifname[dir])) == 0,
			"lc_socket_bind: %s", strerror(errno));
	test_log("thread %i bound to interface %s (%u)", dir, ifname[dir], if_nametoindex(ifname[dir]));
	lc_channel_bind(sock, chan);
	lc_channel_join(chan);

	test_log("thread %i has raw socket %i", dir, lc_socket_raw(sock));

	sem_post(&sem_ready); /* tell send thread we're ready */
	bytes = lc_socket_recv(sock, recvbuf[dir], BUFSIZ, 0);
	test_log("thread %i recv'd '%s'", dir, recvbuf[dir]);
	sem_post(&sem_done); /* tell send thread we're done */

	lc_ctx_free(lctx);
	return arg;
}

static void destroy_interfaces(lc_ctx_t *lctx)
{
	errno = 0;
	for (int i = 0; i < IF_COUNT; i++) {
		test_assert(lc_link_set(lctx, ifname[i], LC_IF_DOWN) == 0, "lc_link_set %s DOWN", ifname[i]);
		perror("lc_link_set");
	}
}

static void disable_dad(char *ifname)
{
	char fname[128];
	char sysvar[] = "/proc/sys/net/ipv6/conf/%s/accept_dad";
	int fd;
	snprintf(fname, 128, sysvar, ifname);
	fd = open(fname, O_WRONLY);
	test_assert(write(fd, "0", 1) == 1, "write");
	close(fd);
}

/* create a bridge with a couple of tap interfaces */
static void create_interfaces(lc_ctx_t *lctx)
{
	errno = 0;
	for (int i = 0; i < IF_COUNT; i++) {
		test_assert(lc_tap_create(ifname[i]) != -1, "lc_tap_create");
		perror("lc_tap_create");
		disable_dad(ifname[i]); /* otherwise we need to sleep 2s for DAD */
		test_assert(lc_link_set(lctx, ifname[i], LC_IF_UP) == 0, "lc_link_set %s UP", ifname[i]);
		perror("lc_link_set");
	}
}

int main(void)
{
	lc_ctx_t * lctx;
	lc_socket_t * sock[IF_COUNT];
	lc_channel_t * chan;
	pthread_attr_t attr = {0};
	pthread_t thread[IF_COUNT];
	struct timespec ts;
	int dir[IF_COUNT] = { 0, 1, 2 };

	test_require_linux();
	test_cap_require(CAP_NET_ADMIN);
	test_name("lc_socket_bind()");

	lctx = lc_ctx_new();
	chan = lc_channel_new(lctx, channel_name);

	create_interfaces(lctx);

	sem_init(&sem_ready, 0, 0);
	sem_init(&sem_done, 0, 0);
	pthread_attr_init(&attr);
	for (int i = 0; i < IF_COUNT; i++) {
		pthread_create(&thread[i], &attr, &recv_thread, &dir[i]);
	}
	pthread_attr_destroy(&attr);

	/* recv threads are ready */
	for (int i = 0; i < IF_COUNT; i++) sem_wait(&sem_ready);
	sem_destroy(&sem_ready);

	for (int i = 0; i < IF_COUNT; i++) {
		sock[i] = lc_socket_new(lctx);
		lc_socket_loop(sock[i], 1);
		lc_channel_bind(sock[i], chan);
		test_assert(lc_socket_bind(sock[i], if_nametoindex(ifname[i])) == 0,
				"lc_socket_bind: %s", strerror(errno));
		lc_channel_send(chan, hail[i], strlen(hail[i]), 0);
	}

	/* wait for recv threads */
	test_assert(!clock_gettime(CLOCK_REALTIME, &ts), "clock_gettime()");
	ts.tv_sec += WAITS;
	for (int i = 0; i < IF_COUNT; i++) {
		test_assert(!sem_timedwait(&sem_done, &ts), "timeout");
	}
	sem_destroy(&sem_done);

	for (int i = 0; i < IF_COUNT; i++) {
		test_log("devoir: %s", recvbuf[i]);
	}

	for (int i = 0; i < IF_COUNT; i++) {
		pthread_cancel(thread[i]);
		pthread_join(thread[i], NULL);
		test_expect(hail[i], recvbuf[i]);
	}

	destroy_interfaces(lctx);
	lc_ctx_free(lctx);

	return fails;
}
