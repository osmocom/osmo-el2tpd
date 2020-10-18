/* Osmocom L2TP daemon for Ericsson L2TP dialect */

/* (C) 2016 by Harald Welte <laforge@gnumonks.org>
 * (C) 2016 by sysmocom - s.f.m.c. GmbH, Author: Alexander Couzens <lynxis@fe80.eu>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/signal.h>

#include "l2tp_protocol.h"
#include "l2tpd.h"
#include "l2tpd_data.h"
#include "l2tpd_fsm.h"
#include "l2tpd_packet.h"
#include "l2tpd_lapd.h"
#include "l2tpd_logging.h"
#include "l2tpd_socket.h"

void *tall_l2tp_ctx;
struct l2tpd_instance *l2i;
/* FIXME: global static instance */

static int l2tp_ip_read_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct msgb *msg = l2tp_msgb_alloc();
	struct sockaddr ss = { 0 };
	socklen_t ss_len = sizeof(ss);
	int rc;

	/* actually read the message from the raw IP socket */
	rc = recvfrom(ofd->fd, msg->data, msg->data_len, 0,
			(struct sockaddr *) &ss, &ss_len);
	if (rc < 0) {
		LOGP(DL2TP, LOGL_ERROR, "recievefrom failed %s\n", strerror(errno));
		return rc;
	}
	msgb_put(msg, rc);
	msg->l1h = msg->data; /* l1h = ip header */

	msgb_pull(msg, 20); /* IPv4 header. FIXME: Should depend on the family */
	msg->l2h = msg->data;
	msg->dst = &ss;

	rc = l2tp_rcvmsg(msg);
	msgb_free(msg);

	return rc;
}

static int l2tpd_instance_start(struct l2tpd_instance *li)
{
	int rc;
	uint8_t dscp = 0xb8;

	INIT_LLIST_HEAD(&li->connections);

	li->l2tp_ofd.when = OSMO_FD_READ;
	li->l2tp_ofd.cb = l2tp_ip_read_cb;
	li->l2tp_ofd.data = li;

	rc = osmo_sock_init_ofd(&li->l2tp_ofd, AF_INET, SOCK_RAW,
				IPPROTO_L2TP, li->cfg.bind_ip, 0, 0);
	if (rc < 0)
		return rc;

	setsockopt(li->l2tp_ofd.fd, IPPROTO_IP, IP_TOS,
		    &dscp, sizeof(dscp));

	return 0;
}

static void signal_handler(int signal)
{
	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
		osmo_signal_dispatch(SS_L_GLOBAL, S_L_GLOBAL_SHUTDOWN, NULL);
		sleep(1);
		exit(0);
		break;
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report
		 * and then return to the caller, who will abort the process */
	case SIGUSR1:
		/* FIXME: call vty report when implementing vty */
		// talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_l2tp_ctx, stderr);
		break;
	case SIGUSR2:
		// talloc_report_full(tall_vty_ctx, stderr);
		break;
	default:
		break;
	}
}

int main(int argc, char **argv)
{
	int rc;

	tall_l2tp_ctx = talloc_named_const(NULL, 0, "l2tpd");
	msgb_talloc_ctx_init(tall_l2tp_ctx, 0);

	signal(SIGINT, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	l2tpd_log_init();


	l2i = talloc_zero(tall_l2tp_ctx, struct l2tpd_instance);
	l2i->cfg.bind_ip = "0.0.0.0";
	l2i->cfg.rsl_oml_path = "/tmp/rsl_oml";
	l2i->cfg.pgsl_path = "/tmp/pgsl";
	l2i->cfg.trau_path = "/tmp/trau";
	/* connection id starts with 1 */
	l2i->next_l_cc_id = 1;
	/* session id starts with 1 */
	l2i->next_l_sess_id = 1;

	rc = l2tpd_instance_start(l2i);
	if (rc < 0)
		exit(1);

	l2i->rsl_oml.name = "RSL/OML";
	l2i->rsl_oml.version_control_header = 1;
	l2i->trau.name = "TRAU";
	l2i->pgsl.name = "P/GSL";
	l2tp_socket_init(&l2i->rsl_oml.state, l2i->cfg.rsl_oml_path, 100, DL2TP);
	l2tp_socket_init(&l2i->trau.state, l2i->cfg.trau_path, 100, DL2TP);
	l2tp_socket_init(&l2i->pgsl.state, l2i->cfg.pgsl_path, 100, DL2TP);

	l2tp_set_read_callback(&l2i->rsl_oml.state, unix_read_cb);
	l2tp_set_read_callback(&l2i->pgsl.state, unix_read_cb);
	l2tp_set_read_callback(&l2i->trau.state, unix_read_cb);

	while (1) {
		osmo_select_main(0);
	}
}
