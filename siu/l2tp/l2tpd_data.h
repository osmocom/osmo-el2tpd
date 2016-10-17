#pragma once

#include "l2tpd.h"

struct l2tpd_connection *
l2tpd_cc_find_by_l_cc_id(struct l2tpd_instance *inst, uint32_t l_cc_id);

struct l2tpd_connection *
l2tpd_cc_alloc(struct l2tpd_instance *inst);

struct l2tpd_session *
l2tpd_sess_alloc(struct l2tpd_connection *conn);
