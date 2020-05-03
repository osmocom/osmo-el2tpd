#pragma once

int lapd_lapd_to_ehdlc(struct l2tpd_instance *l2i, struct msgb *msg);
int lapd_ehdlc_to_lapd(struct l2tpd_instance *l2i, struct l2tpd_session *session, struct msgb *msg);
int unix_read_cb(struct osmo_fd *fd);
