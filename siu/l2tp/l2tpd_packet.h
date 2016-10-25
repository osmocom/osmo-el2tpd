#pragma once

struct msgb;
struct l2tpd_connection;
struct l2tpd_session;

/* control connection management */
int l2tp_tx_scc_rp(struct l2tpd_connection *l2c);
int l2tp_tx_stop_ccn(struct l2tpd_connection *l2c);
int l2tp_tx_stop_ccn_msg(struct msgb *old)
int l2tp_tx_tc_rq(struct l2tpd_connection *l2c);
int l2tp_tx_altc_rq_superchannel(struct l2tpd_connection *l2c);
int l2tp_tx_altc_rq_timeslot(struct l2tpd_connection *l2c);
int l2tp_tx_ack(struct l2tpd_connection *l2c);

/* session management */
int l2tp_tx_ic_rp(struct l2tpd_session *l2s);
int l2tp_tx_hello(struct l2tpd_session *l2s);

int l2tp_rcvmsg(struct msgb *msg);

struct msgb *l2tp_msgb_alloc(void);
