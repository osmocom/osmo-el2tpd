#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <arpa/inet.h>

#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/fsm.h>

#include "l2tp_protocol.h"
#include "l2tpd.h"
#include "l2tpd_data.h"
#include "l2tpd_fsm.h"
#include "l2tpd_packet.h"

struct l2tpd_instance *l2i;
/* FIXME: global static instance */

static int l2tp_ip_read_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct msgb *msg = l2tp_msgb_alloc();
	struct sockaddr ss;
	socklen_t ss_len = sizeof(ss);
	int rc;

	/* actually read the message from the raw IP socket */
	rc = recvfrom(ofd->fd, msg->data, msg->data_len, 0,
			(struct sockaddr *) &ss, &ss_len);
	if (rc < 0)
		return rc;
	msgb_put(msg, rc);
	msg->l1h = msg->data; /* l1h = ip header */

	msgb_pull(msg, 20); /* IPv4 header. FIXME: Should depend on the family */
	msg->l2h = msg->data;
	msg->dst = &ss;

	return l2tp_rcvmsg(msg);
}

static int l2tpd_instance_start(struct l2tpd_instance *li)
{
	int rc;

	INIT_LLIST_HEAD(&li->connections);

	li->l2tp_ofd.when = BSC_FD_READ;
	li->l2tp_ofd.cb = l2tp_ip_read_cb;
	li->l2tp_ofd.data = li;

	rc = osmo_sock_init_ofd(&li->l2tp_ofd, AF_INET, SOCK_RAW,
				IPPROTO_L2TP, li->cfg.bind_ip, 0, 0);
	if (rc < 0)
		return rc;

	return 0;
}

/* default categories */
static struct log_info_cat l2tp_categories[] = {
	[DL2TP] = {
		.name = "DL2TP",
		.description = "L2TP logging messages",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static const struct log_info l2tp_log_info = {
	.cat = l2tp_categories,
	.num_cat = ARRAY_SIZE(l2tp_categories),
};

int main(int argc, char **argv)
{
	int rc;
	struct log_target *stderr_target;
	void *tall_l2tp_ctx = talloc_named_const(NULL, 0, "l2tpd");

	/* register fsms */
	osmo_fsm_register(&l2tp_cc_fsm);
	osmo_fsm_register(&l2tp_ic_fsm);

	l2i = talloc_zero(tall_l2tp_ctx, struct l2tpd_instance);
	l2i->cfg.bind_ip = "0.0.0.0";

	rc = l2tpd_instance_start(l2i);
	if (rc < 0)
		exit(1);

	log_init(&l2tp_log_info, NULL);
	stderr_target = log_target_create_stderr();
	log_add_target(stderr_target);
	log_set_print_filename(stderr_target, 0);


	while (1) {
		osmo_select_main(0);
	}
}
