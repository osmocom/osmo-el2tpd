#pragma once

#include "l2tpd.h"

struct sockaddr;

/* l2tp connection */
struct l2tpd_connection *
l2tpd_cc_find_by_sockaddr(struct l2tpd_instance *inst, struct sockaddr *ss, int ss_len);

struct l2tpd_connection *
l2tpd_cc_find_by_l_cc_id(struct l2tpd_instance *inst, uint32_t l_cc_id);

struct l2tpd_connection *
l2tpd_cc_alloc(struct l2tpd_instance *inst);

/* l2tp session */
struct l2tpd_session *
l2tpd_sess_alloc(struct l2tpd_connection *conn);

struct l2tpd_session *
l2tpd_sess_find_by_l_s_id(struct l2tpd_connection *conn, uint32_t session_id);
