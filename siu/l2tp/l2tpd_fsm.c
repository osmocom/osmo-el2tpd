
#include <osmocom/core/fsm.h>

#include "l2tp_protocol.h"

#include "l2tpd.h"
#include "l2tpd_packet.h"
#include "l2tpd_data.h"
#include "l2tpd_fsm.h"

#define S(x)	(1 << (x))

static void l2tp_ctrl_s_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct l2tpd_connection *l2c = fi->priv;

	switch (event) {
	case L2CC_E_RX_SCCRQ:
		if (!l2tp_tx_scc_rp(l2c)) {
			osmo_fsm_inst_state_chg(fi, L2CC_S_WAIT_CTL_CONN, 0, 0);
		}
		break;
	}
}

static void l2tp_ctrl_s_wait_ctl_conn(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct l2tpd_connection *l2c = fi->priv;

	switch (event) {
	case L2CC_E_RX_SCCCN:
		if (!l2tp_tx_ack(l2c)) {
			osmo_fsm_inst_state_chg(fi, L2CC_S_ESTABLISHED, 0, 0);
			osmo_fsm_inst_dispatch(l2c->conf_fsm, L2CONF_E_TX_TCRQ, data);
		}
		break;
	}
}

static void l2tp_ctrl_s_established(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
}


static void l2tp_ctrl_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct l2tpd_connection *l2c = fi->priv;

	switch (event) {
	case L2CC_E_LOCAL_CLOSE_REQ:
		l2tp_tx_stop_ccn(l2c);
		osmo_fsm_inst_state_chg(fi, L2CC_S_INIT, 0, 0);
		/* FIXME: teardown instead of INIT */
		break;
	case L2CC_E_RX_STOP_CCN:
		l2tp_tx_ack(l2c);
		osmo_fsm_inst_state_chg(fi, L2CC_S_INIT, 0, 0);
		/* FIXME: tear down whole l2c */
		break;
	case L2CC_E_RX_HELLO:
		l2tp_tx_ack(l2c);
		break;
	}
}

static const struct value_string l2tp_cc_events[] = {
	{ L2CC_E_LOCAL_CLOSE_REQ,	"LOCAL-CLOSE" },
	{ L2CC_E_RX_SCCRQ,		"RX-SCCRQ" },
	{ L2CC_E_RX_SCCRP,		"RX-SCCRP" },
	{ L2CC_E_RX_SCCCN,		"RX-SCCCN" },
	{ L2CC_E_RX_STOP_CCN,		"RX-STOPCCN" },
	{ L2CC_E_RX_HELLO,		"RX-HELLO" },
	{ 0, NULL }
};

static const struct osmo_fsm_state l2tp_ctrl_states[] = {
	[L2CC_S_INIT] = {
		.in_event_mask = S(L2CC_E_RX_SCCRQ),
		.out_state_mask = S(L2CC_S_WAIT_CTL_CONN) | S(L2CC_S_INIT),
		.name = "INIT",
		.action = l2tp_ctrl_s_init,
	},
	[L2CC_S_WAIT_CTL_CONN] = {
		.in_event_mask = S(L2CC_E_RX_SCCCN),
		.out_state_mask = S(L2CC_S_ESTABLISHED) |
				  S(L2CC_S_INIT),
		.name = "WAIT_CTL_CONN",
		.action = l2tp_ctrl_s_wait_ctl_conn,
	},
	[L2CC_S_ESTABLISHED] = {
		.in_event_mask = 0,
		.out_state_mask = S(L2CC_S_INIT),
		.name = "ESTABLISHED",
		.action = l2tp_ctrl_s_established,
	}
};

struct osmo_fsm l2tp_cc_fsm = {
	.name = "L2TP-CC",
	.states = l2tp_ctrl_states,
	.num_states = ARRAY_SIZE(l2tp_ctrl_states),
	.log_subsys = 0,
	.event_names = l2tp_cc_events,
	.allstate_event_mask = S(L2CC_E_RX_HELLO) | S(L2CC_E_LOCAL_CLOSE_REQ) | S(L2CC_E_RX_STOP_CCN),
	.allstate_action = l2tp_ctrl_allstate,
};

/* l2tp conf fsm */

static void l2tp_conf_s_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct l2tpd_connection *l2c = fi->priv;

	switch (event) {
		case L2CONF_E_TX_TCRQ:
			l2tp_tx_tc_rq(l2c);
			osmo_fsm_inst_state_chg(fi, L2CONF_S_WAIT_FOR_TCRP, 0, 0);
			break;
	}
}

static void l2tp_conf_s_wait_for_tcrp(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct l2tpd_connection *l2c = fi->priv;

	switch (event) {
	case L2CONF_E_RX_TCRP:
		l2tp_tx_ack(l2c);
		osmo_fsm_inst_state_chg(fi, L2CONF_S_WAIT_FOR_TC_SESSIONS, 0, 0);
		break;
	}
}

static void l2tp_conf_s_wait_for_tc_sessions(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct l2tpd_connection *l2c = fi->priv;
	struct l2tpd_session *l2s;
	int i = 0;

	switch (event) {
		case L2CONF_E_ESTABLISH_SESSION:
			llist_for_each_entry(l2s, &l2c->sessions, list) {
				i++;
			}
			LOGP(DL2TP, LOGL_ERROR, "Found %d sessions\n", i);
			if (i >= 3) {
				osmo_fsm_inst_state_chg(fi, L2CONF_S_WAIT_FOR_ALTCRP, 0, 0);
				l2tp_tx_altc_rq_timeslot(l2c);
			}
			break;
	}
}


static void l2tp_conf_s_wait_for_altcrp(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct l2tpd_connection *l2c = fi->priv;

	switch (event) {
	case L2CONF_E_RX_ALTCRP:
		l2tp_tx_ack(l2c);
		osmo_fsm_inst_state_chg(fi, L2CONF_S_WAIT_FOR_ALTC_SESSIONS, 0, 0);
		break;
	}
}

static void l2tp_conf_s_wait_for_altc_sessions(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct l2tpd_connection *l2c = fi->priv;
	struct l2tpd_session *l2s;
	int i = 0;

	switch (event) {
		case L2CONF_E_ESTABLISH_SESSION:
			llist_for_each_entry(l2s, &l2c->sessions, list) {
				i++;
			}
			LOGP(DL2TP, LOGL_ERROR, "Found %d sessions\n", i);

			if (i >= 4) {
				osmo_fsm_inst_state_chg(fi, L2CONF_S_ESTABLISHED, 0, 0);
			}
			break;
	}
}


static void l2tp_conf_s_established(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
}

static void l2tp_conf_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case L2CONF_E_LOCAL_CLOSE_REQ:
		osmo_fsm_inst_state_chg(fi, L2CONF_S_INIT, 0, 0);
		/* FIXME: teardown instead of INIT */
		break;
	}
}

static const struct value_string l2tp_conf_events[] = {
	{ L2CONF_E_LOCAL_CLOSE_REQ,	"LOCAL-CLOSE" },
	{ L2CONF_E_TX_TCRQ,		"TX-TCRQ" },
	{ L2CONF_E_RX_TCRP,		"RX-TCRP" },
	{ L2CONF_E_RX_ALTCRP,		"RX-ALTCRP" },
	{ L2CONF_E_ESTABLISH_SESSION, "RX-InCall-Connect" },
	{ 0, NULL }
};

static const struct osmo_fsm_state l2tp_conf_states[] = {
	[L2CONF_S_INIT] = {
		.in_event_mask = S(L2CONF_E_TX_TCRQ),
		.out_state_mask = S(L2CONF_S_WAIT_FOR_TCRP) |
				  S(L2CONF_S_INIT),
		.name = "INIT",
		.action = l2tp_conf_s_init,
	},
	[L2CONF_S_WAIT_FOR_TCRP] = {
		.in_event_mask = S(L2CONF_E_RX_TCRP),
		.out_state_mask = S(L2CONF_S_WAIT_FOR_TC_SESSIONS) |
				  S(L2CONF_S_INIT),
		.name = "WAIT_FOR_TCRP",
		.action = l2tp_conf_s_wait_for_tcrp,
	},
	[L2CONF_S_WAIT_FOR_TC_SESSIONS] = {
		.in_event_mask = S(L2CONF_E_ESTABLISH_SESSION),
		.out_state_mask = S(L2CONF_S_WAIT_FOR_ALTCRP) |
				  S(L2CONF_S_INIT),
		.name = "WAIT_FOR_TC_SESSIONS",
		.action = l2tp_conf_s_wait_for_tc_sessions,
	},
	[L2CONF_S_WAIT_FOR_ALTCRP] = {
		.in_event_mask = S(L2CONF_E_RX_ALTCRP),
		.out_state_mask = S(L2CONF_S_WAIT_FOR_ALTC_SESSIONS) |
				  S(L2CONF_S_INIT),
		.name = "WAIT_FOR_ALTCRP",
		.action = l2tp_conf_s_wait_for_altcrp,
	},
	[L2CONF_S_WAIT_FOR_ALTC_SESSIONS] = {
		.in_event_mask = S(L2CONF_E_ESTABLISH_SESSION),
		.out_state_mask = S(L2CONF_S_ESTABLISHED) |
				  S(L2CONF_S_INIT),
		.name = "WAIT_FOR_ALTC_SESSIONS",
		.action = l2tp_conf_s_wait_for_altc_sessions,
	},
	[L2CONF_S_ESTABLISHED] = {
		.in_event_mask = 0,
		.out_state_mask = S(L2CONF_S_INIT),
		.name = "ESTABLISHED",
		.action = l2tp_conf_s_established,
	},
};

struct osmo_fsm l2tp_conf_fsm = {
	.name = "L2TP-CONF",
	.states = l2tp_conf_states,
	.num_states = ARRAY_SIZE(l2tp_conf_states),
	.log_subsys = 0,
	.event_names = l2tp_conf_events,
	.allstate_event_mask = S(L2CONF_E_LOCAL_CLOSE_REQ),
	.allstate_action = l2tp_conf_allstate,
};

/* l2tp ic/session fsm */
static void l2tp_ic_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case L2IC_E_RX_CDN:
		/* Disconnect the call */
		break;
	case L2IC_E_LOCAL_CLOSE_REQ:
		/* FIXME: Send CDN */
		/* Disconnect the call */
		break;
	}
}

static void l2tp_ic_s_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct l2tpd_session *l2s = fi->priv;

	switch (event) {
	case L2IC_E_RX_ICRQ:
		if (!l2tp_tx_ic_rp(l2s))
			osmo_fsm_inst_state_chg(fi, L2IC_S_WAIT_CONN, 0, 0);
		break;
	}
}

static void l2tp_ic_s_wait_conn(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct l2tpd_session *l2s = (struct l2tpd_session *) fi->priv;
	struct l2tpd_connection *l2c = l2s->connection;

	switch (event) {
	case L2IC_E_RX_ICCN:
		/* ICCN received */
		if (!l2tp_tx_ack(l2c)) {
			osmo_fsm_inst_state_chg(fi, L2IC_S_ESTABLISHED, 0, 0);
			osmo_fsm_inst_dispatch(l2c->conf_fsm, L2CONF_E_ESTABLISH_SESSION, data);
			switch (l2s->remote_end_id) {
				/* FIXME: kick out the old session */
				case TC_GROUP_PGSL:
					l2i->pgsl.session = l2s;
					break;
				case TC_GROUP_RSL_OML:
					l2i->rsl_oml.session = l2s;
					break;
				case TC_GROUP_TRAU:
					l2i->trau.session = l2s;
					break;
			}
		}
	}
}

static void l2tp_ic_s_established(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	/* FIXME: remove old session if it got dealloc from l2i->trau.session etc. */
}


static const struct value_string l2tp_ic_names[] = {
	{ L2IC_E_RX_ICRQ, "RX-InCall-Req" },
	{ L2IC_E_RX_ICCN, "RX-InCall-Connect" },
	{ L2IC_E_RX_CDN,  "RX-CallDisc-Notif" },
	{ L2IC_E_LOCAL_CLOSE_REQ, "Local-Close-Req" },
	{ 0, NULL }
};

static const struct osmo_fsm_state l2tp_ic_states[] = {
	[L2IC_S_INIT] = {
		.in_event_mask = S(L2IC_E_RX_ICRQ),
		.out_state_mask = S(L2IC_S_WAIT_CONN),
		.name = "INIT",
		.action = l2tp_ic_s_init,
	},
	[L2IC_S_WAIT_CONN] = {
		.in_event_mask = S(L2IC_E_RX_ICCN),
		.out_state_mask = S(L2IC_S_INIT) |
				  S(L2IC_S_ESTABLISHED),
		.name = "WAIT-CONN",
		.action = l2tp_ic_s_wait_conn,
	},
	[L2IC_S_ESTABLISHED] = {
		.in_event_mask = 0,
		.out_state_mask = 0,
		.name = "ESTABLISHED",
		.action = l2tp_ic_s_established,
	},
};

struct osmo_fsm l2tp_ic_fsm = {
	.name = "L2TP-IC",
	.states = l2tp_ic_states,
	.num_states = ARRAY_SIZE(l2tp_ic_states),
	.log_subsys = 0,
	.event_names = l2tp_ic_names,
	.allstate_event_mask = S(L2IC_E_RX_CDN) | S(L2IC_E_LOCAL_CLOSE_REQ),
	.allstate_action = l2tp_ic_allstate,
};
