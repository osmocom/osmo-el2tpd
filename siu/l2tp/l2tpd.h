#pragma once

#include <stdint.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>

static inline void *msgb_l2tph(struct msgb *msg)
{
	return msg->l2h;
}

static inline unsigned int msgb_l2tplen(const struct msgb *msg)
{
	return msgb_l2len(msg);
}

/* identifiers of a peer on a L2TP connection */
struct l2tpd_peer {
	char *host_name;
	uint32_t router_id;
	/* Control Connection ID */
	uint32_t ccid;
};

/* A L2P connection between two peers. exists once, contains many
 * sessions */
struct l2tpd_connection {
	/* global list of connections */
	struct llist_head list;
	/* list of sessions in this conncetion */
	struct llist_head sessions;
	/* local and remote peer */
	struct l2tpd_peer local;
	struct l2tpd_peer remote;
	/* seq nr of next to-be-sent frame */
	uint16_t next_tx_seq_nr;
	/* seq nr of expected next Rx frame */
	uint16_t next_rx_seq_nr;
	/* next local session id */
	uint32_t next_l_sess_id;
	/* finite state machine for connection */
	struct osmo_fsm_inst *fsm;
};

/* A L2TP session within a connection */
struct l2tpd_session {
	/* our link into the connection.sessions */
	struct llist_head list;
	/* local session ID */
	uint32_t l_sess_id;
	/* remote session ID */
	uint32_t r_sess_id;
	/* pseudowire type */
	uint16_t pw_type;
	/* seq nr of next to-be-sent frame */
	uint32_t next_tx_seq_nr;
	/* seq nr of expected next Rx frame */
	uint32_t next_rx_seq_nr;
	/* finite state machine for call/session */
	struct osmo_fsm_inst *fsm;

	/* TODO: sockets for TRAU and PCU */
};

struct l2tpd_instance {
	/* list of l2tpd_connection */
	struct llist_head connections;
	uint32_t next_l_cc_id;

	struct osmo_fd l2tp_ofd;

	struct {
		const char *bind_ip;
	} cfg;
};

enum {
	DL2TP,
};
