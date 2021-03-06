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

#include <osmocom/core/talloc.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/fsm.h>

#include "l2tpd.h"
#include "l2tpd_data.h"
#include "l2tpd_fsm.h"


/* FIXME: use libosmocore osmo_sockaddr_equal when its upstream */
static int sockaddr_equal(const struct sockaddr *a,
			  const struct sockaddr *b, unsigned int len)
{
	struct sockaddr_in *sin_a, *sin_b;
	struct sockaddr_in6 *sin6_a, *sin6_b;

	if (a->sa_family != b->sa_family)
		return 0;

	switch (a->sa_family) {
	case AF_INET:
		sin_a = (struct sockaddr_in *)a;
		sin_b = (struct sockaddr_in *)b;
		if (!memcmp(&sin_a->sin_addr, &sin_b->sin_addr,
			    sizeof(struct in_addr)))
			return 1;
		break;
	case AF_INET6:
		sin6_a = (struct sockaddr_in6 *)a;
		sin6_b = (struct sockaddr_in6 *)b;
		if (!memcmp(&sin6_a->sin6_addr, &sin6_b->sin6_addr,
			    sizeof(struct in6_addr)))
			return 1;
		break;
	}
	return 0;
}

/* Find a connection for given local control connection id */
struct l2tpd_connection *
l2tpd_cc_find_by_l_cc_id(struct l2tpd_instance *inst, uint32_t l_cc_id)
{
	struct l2tpd_connection *l2c;
	llist_for_each_entry(l2c, &inst->connections, list) {
		if (l2c->local.ccid == l_cc_id)
			return l2c;
	}
	return NULL;
}

struct l2tpd_connection *
l2tpd_cc_find_by_sockaddr(struct l2tpd_instance *inst, struct sockaddr *ss, int ss_len)
{
	struct l2tpd_connection *l2c;
	llist_for_each_entry(l2c, &inst->connections, list) {
		if (sockaddr_equal(ss, &l2c->remote.ss, ss_len))
			return l2c;
	}
	return NULL;
}

struct l2tpd_connection *
l2tpd_cc_alloc(struct l2tpd_instance *l2i)
{
	struct l2tpd_connection *l2c = talloc_zero(l2i, struct l2tpd_connection);
	char id_str[12] = {0};


	INIT_LLIST_HEAD(&l2c->sessions);
	l2c->local.ccid = l2i->next_l_cc_id++;
	l2c->ack.timer.cb = l2tpd_explicit_ack_cb;
	l2c->ack.timer.data = l2c;

	snprintf(id_str, 12, "%d", l2c->local.ccid);

	llist_add(&l2c->list, &l2i->connections);
	l2c->fsm = osmo_fsm_inst_alloc(&l2tp_cc_fsm, l2c, l2c, LOGL_DEBUG, id_str);
	l2c->conf_fsm = osmo_fsm_inst_alloc(&l2tp_conf_fsm, l2c, l2c, LOGL_DEBUG, id_str);

	return l2c;
}

struct l2tpd_session *
l2tpd_sess_alloc(struct l2tpd_instance *l2i, struct l2tpd_connection *conn)
{
	struct l2tpd_session *l2s = talloc_zero(conn, struct l2tpd_session);
	char id_str[12] = {0};

	l2s->l_sess_id = l2i->next_l_sess_id++;
	snprintf(id_str, 12, "%d", l2s->l_sess_id);

	llist_add(&l2s->list, &conn->sessions);
	l2s->fsm = osmo_fsm_inst_alloc(&l2tp_ic_fsm, l2s, l2s, LOGL_DEBUG, id_str);
	l2s->connection = conn;

	return l2s;
}

struct l2tpd_session *
l2tpd_sess_find_by_l_s_id(struct l2tpd_instance *l2i, uint32_t session_id)
{
	struct l2tpd_session *l2s;
	struct l2tpd_connection *l2c;
	llist_for_each_entry(l2c, &l2i->connections, list) {
		llist_for_each_entry(l2s, &l2c->sessions, list) {
			if (l2s->l_sess_id == session_id)
				return l2s;
		}
	}
	return NULL;
}
