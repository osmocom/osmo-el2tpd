
#include <osmocom/core/fsm.h>

#include "l2tpd_packet.h"
#include "l2tpd_fsm.h"

#define S(x)	(1 << (x))

static void l2tp_ctrl_s_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct l2tpd_connection *l2c = fi->priv;
	if (!l2tp_tx_scc_rp(l2c)) {
		osmo_fsm_inst_state_chg(fi, L2CC_S_WAIT_CTL_CONN, 0, 0);
	}
}

static void l2tp_ctrl_s_wait_ctl_conn(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct l2tpd_connection *l2c = fi->priv;

	switch (event) {
	case L2CC_E_LOCAL_CLOSE_REQ:
		l2tp_tx_stop_ccn(l2c);
		osmo_fsm_inst_state_chg(fi, L2CC_S_INIT, 0, 0);
		/* FIXME: teardown */
		break;
	case L2CC_E_RX_SCCCN:
		l2tp_tx_ack(l2c);
		osmo_fsm_inst_state_chg(fi, L2CC_S_ESTABLISHED, 0, 0);
		break;
	case L2CC_E_RX_STOP_CCN:
		l2tp_tx_ack(l2c);
		/* FIXME: tear down whole l2c */
		break;
	}
}

static void l2tp_ctrl_s_established(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct l2tpd_connection *l2c = fi->priv;

	switch (event) {
	case L2CC_E_LOCAL_CLOSE_REQ:
		l2tp_tx_stop_ccn(l2c);
		osmo_fsm_inst_state_chg(fi, L2CC_S_INIT, 0, 0);
		/* FIXME: teardown */
		break;
	case L2CC_E_RX_STOP_CCN:
		l2tp_tx_ack(l2c);
		/* FIXME: tear down whole l2c */
		break;
	}
}

static const struct value_string l2tp_cc_events[] = {
	{ L2CC_E_LOCAL_CLOSE_REQ,	"LOCAL-CLOSE" },
	{ L2CC_E_RX_SCCRQ,		"RX-SCCRQ" },
	{ L2CC_E_RX_SCCRP,		"RX-SCCRP" },
	{ L2CC_E_RX_SCCCN,		"RX-SCCCN" },
	{ L2CC_E_RX_STOP_CCN,		"RX-STOPCCN" },
	{ 0, NULL }
};

static const struct osmo_fsm_state l2tp_ctrl_states[] = {
	[L2CC_S_INIT] = {
		.in_event_mask = S(L2CC_E_RX_SCCRQ),
		.out_state_mask = S(L2CC_S_WAIT_CTL_CONN),
		.name = "INIT",
		.action = l2tp_ctrl_s_init,
	},
	[L2CC_S_WAIT_CTL_CONN] = {
		.in_event_mask = S(L2CC_E_RX_SCCCN) |
				 S(L2CC_E_LOCAL_CLOSE_REQ),
		.out_state_mask = S(L2CC_S_ESTABLISHED) |
				  S(L2CC_S_INIT),
		.name = "WAIT_CTL_CONN",
		.action = l2tp_ctrl_s_wait_ctl_conn,
	},
	[L2CC_S_ESTABLISHED] = {
		.in_event_mask = S(L2CC_E_LOCAL_CLOSE_REQ) |
				 S(L2CC_E_RX_STOP_CCN),
		.out_state_mask = S(L2CC_S_ESTABLISHED) |
				  S(L2CC_S_INIT),
		.name = "ESTABLISHED",
		.action = l2tp_ctrl_s_established,
	},
};

struct osmo_fsm l2tp_cc_fsm = {
	.name = "L2TP-CC",
	.states = l2tp_ctrl_states,
	.num_states = ARRAY_SIZE(l2tp_ctrl_states),
	.log_subsys = 0,
	.event_names = l2tp_cc_events,
};

static void l2tp_ic_s_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	/* ICRQ was received */
	OSMO_ASSERT(event == L2IC_E_RX_ICRQ);
	/* FIXME: Send ICRP */
	osmo_fsm_inst_state_chg(fi, L2IC_S_WAIT_CONN, 0, 0);
}

static void l2tp_ic_s_wait_conn(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	/* ICCN wsa received */
	OSMO_ASSERT(event == L2IC_E_RX_ICCN);
	osmo_fsm_inst_state_chg(fi, L2IC_S_ESTABLISHED, 0, 0);
}

static void l2tp_ic_s_established(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
}

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

