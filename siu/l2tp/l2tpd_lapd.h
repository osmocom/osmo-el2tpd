#pragma once

int lapd_lapd_to_ehdlc(struct l2tpd_instance *l2i, struct msgb *msg);
int lapd_ehdlc_to_lapd(struct l2tpd_instance *l2i, struct l2tpd_session *session, struct msgb *msg);
int lapd_send_xid(struct l2tpd_instance *l2i, struct l2tpd_session *l2s, int sapi, int tei);
int unix_rsl_oml_cb(struct osmo_fd *fd);
int unix_trau_cb(struct osmo_fd *fd);
int unix_pgsl_cb(struct osmo_fd *fd);
