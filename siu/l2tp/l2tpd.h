#pragma once

#include <stdint.h>

#include <arpa/inet.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>

#include "l2tpd_socket.h"

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
	struct sockaddr ss;
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
	/* finite state machine for connection */
	struct osmo_fsm_inst *fsm;
	/* finite state machine for traffic channels */
	struct osmo_fsm_inst *conf_fsm;
};

/* A L2TP session within a connection */
struct l2tpd_session {
	/* our conncetion */
	struct l2tpd_connection *connection;
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
	/* remote end id. TCRQ & ALTRQ configures the bundling ids to TEI/SAPIs.
	 * In ICRQ the remote end id is used as bundling id */
	uint8_t remote_end_id;
	/* finite state machine for call/session */
	struct osmo_fsm_inst *fsm;

	/* TODO: sockets for TRAU and PCU */
};

struct traffic_channel {
	struct l2tp_socket_state state;
	struct l2tpd_session *session;
};

struct l2tpd_instance {
	/* list of l2tpd_connection */
	struct llist_head connections;
	/* next connection id */
	uint32_t next_l_cc_id;
	/* next local session id */
	uint32_t next_l_sess_id;

	struct osmo_fd l2tp_ofd;
	/* unix sockets */

	struct traffic_channel rsl_oml;
	struct traffic_channel trau;
	struct traffic_channel pgsl;

	struct {
		const char *bind_ip;
		const char *rsl_oml_path;
		const char *pgsl_path;
		const char *trau_path;
	} cfg;
};

enum {
	DL2TP,
};

extern struct l2tpd_instance *l2i;
