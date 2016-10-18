#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/linuxlist.h>

#include "l2tpd.h"
#include "l2tpd_data.h"

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
l2tpd_cc_alloc(struct l2tpd_instance *inst)
{
	struct l2tpd_connection *l2c = talloc_zero(inst, struct l2tpd_connection);

	INIT_LLIST_HEAD(&l2c->sessions);
	l2c->local.ccid = inst->next_l_cc_id++;

	llist_add(&l2c->list, &inst->connections);

	return l2c;
}



struct l2tpd_session *
l2tpd_sess_alloc(struct l2tpd_connection *conn)
{
	struct l2tpd_session *l2s = talloc_zero(conn, struct l2tpd_session);

	l2s->l_sess_id = conn->next_l_sess_id++;

	llist_add(&l2s->list, &conn->sessions);

	return l2s;
}

struct l2tpd_session *
l2tpd_sess_find_by_l_s_id(struct l2tpd_connection *conn, uint32_t session_id)
{
	struct l2tpd_session *l2s;
	llist_for_each_entry(l2s, &conn->sessions, list) {
		if (l2s->l_sess_id == session_id)
			return l2s;
	}
	return NULL;
}
