#include <stdint.h>

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/timer.h>

int socket_read(struct osmo_fd *bfd, unsigned int flags)
{
	struct msgb *msg = msgb_alloc(1500, "rx unix data");
	int rc;

	printf("Socket read called\n");
	/* actually read the message from the raw IP socket */
	rc = read(bfd->fd, msg->data, msg->data_len);
	if (rc < 0) {
		printf("recievefrom failed %s\n", strerror(errno));
		return rc;
	}
	msgb_put(msg, rc);
	printf("Recv data\n");
	printf(msgb_hexdump(msg));
	printf("\n");

	msgb_free(msg);
	return 0;
}

int connect_bfd(struct osmo_fd *bfd, const char *sock_path)
{
	int rc = 0;

	bfd->when = BSC_FD_READ;
	bfd->cb = socket_read;
	bfd->fd = osmo_sock_unix_init(SOCK_SEQPACKET, 0, sock_path,OSMO_SOCK_F_CONNECT);

	rc = osmo_fd_register(bfd);

	return rc;
}

struct osmo_timer_list timer;

void timer_cb(void *priv)
{
	struct osmo_fd *bfd = priv;
	const uint8_t xid_62_62[16] = {
		0xfa, 0x7d, 0xaf, 0x82, 0x80, 0x00, 0x09, 0x07, 0x01, 0x0b, 0x09, 0x01, 0x0e, 0x08, 0x01, 0x03
	};
	const uint8_t xid_0_1[16] = {
		0x02, 0x03, 0xaf, 0x82, 0x80, 0x00, 0x09, 0x07, 0x01, 0x0b, 0x09, 0x01, 0x0e, 0x08, 0x01, 0x03
	};

	const uint8_t xid_62_1[16] = {
		0xfa, 0x03, 0xaf, 0x82, 0x80, 0x00, 0x09, 0x07, 0x01, 0x0b, 0x09, 0x01, 0x0e, 0x08, 0x01, 0x03
	};

	const uint8_t xid_sabm[3] = {
		0xfa, 0x03, 0x7f,
	};

	printf("Timer called\n");
	write(bfd->fd, xid_62_62, sizeof(xid_62_62));
//	write(bfd->fd, xid_0_1, sizeof(xid_0_1));
//	write(bfd->fd, xid_62_1, sizeof(xid_62_1));
//	write(bfd->fd, xid_sabm, sizeof(xid_sabm));

	/* 300 ms */
	osmo_timer_schedule(&timer, 0, 300000);
}

int main(int argc, const char *argv[])
{
	struct osmo_fd bfd;

	void *tall_test_ctx = talloc_named_const(NULL, 1, "l2tp test context");
	if (!tall_test_ctx)
	    abort();

	msgb_talloc_ctx_init(tall_test_ctx, 0);
	if (connect_bfd(&bfd, "/tmp/rsl_oml")) {
		printf("Can not connect");
		exit(1);
	}

	timer.cb = timer_cb;
	timer.data = &bfd;

	osmo_timer_schedule(&timer, 3, 0);

	for (;;)
	    osmo_select_main(0);

	return EXIT_SUCCESS;
}
