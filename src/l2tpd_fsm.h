#pragma once
/* (C) 2016 by Harald Welte <laforge@gnumonks.org>
 * (C) 2016 by sysmocom - s.f.m.c. GmbH, Author: Alexander Couzens <lynxis@fe80.eu>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <osmocom/core/fsm.h>

enum l2tpd_ctrl_con_event {
#if 0
	/* Local open request (not applicable on server */
	L2CC_E_LOCAL_OPEN_REQ,
#endif
	/* Local close request */
	L2CC_E_LOCAL_CLOSE_REQ,
	/* Received SCC Request */
	L2CC_E_RX_SCCRQ,
	/* Received SCC Reply */
	L2CC_E_RX_SCCRP,
	/* Received SCC Connected */
	L2CC_E_RX_SCCCN,
	/* Received Stop CCN */
	L2CC_E_RX_STOP_CCN,
	/* Received a HELLO / Keepalive */
	L2CC_E_RX_HELLO,
};

enum l2tpd_ctrl_con_state {
	/* Before we receive SCCRQ*/
	L2CC_S_INIT,
	/* After we sent SCCRP, waiting for SCCCN */
	L2CC_S_WAIT_CTL_CONN,
	/* Control Conncetion is established */
	L2CC_S_ESTABLISHED,
};

enum l2tpd_in_call_event {
#if 0
	L2IC_E_START,
	/* Recieved Incoming Call Reply */
	L2IC_E_RX_ICRP,
	/* Control Connection has Opened */
	L2IC_E_CTRL_CONN_OPEN,
#endif
	/* Received Incoming Call Request */
	L2IC_E_RX_ICRQ,
	/* Received Incoming Call Connect */
	L2IC_E_RX_ICCN,
	/* Received Call Disconnect Notify */
	L2IC_E_RX_CDN,
	/* Local Close Request */
	L2IC_E_LOCAL_CLOSE_REQ,
};
extern struct osmo_fsm l2tp_cc_fsm;

/* ICRQ recipient */
enum l2tpd_in_call_state {
	/* Waiting for ICRQ */
	L2IC_S_INIT,
	/* Waiting for ICCN */
	L2IC_S_WAIT_CONN,
	L2IC_S_ESTABLISHED,
};
extern struct osmo_fsm l2tp_ic_fsm;

enum l2tpd_configure_event {
	/* sent the TC rq within state machine */
	L2CONF_E_TX_TCRQ,
	/* received TC RP */
	L2CONF_E_RX_TCRP,
	/* l2tp session setted up */
	L2CONF_E_ESTABLISH_SESSION,
	/* received ALTC RP */
	L2CONF_E_RX_ALTCRP,
	/* Local Close Request */
	L2CONF_E_LOCAL_CLOSE_REQ,
};

enum l2tpd_configure_state {
	/* initial state, sent out TCRQ */
	L2CONF_S_INIT,
	/* Waiting for TCRP */
	L2CONF_S_WAIT_FOR_TCRP,
	/* Wait until all l2tp sessions of tcrp setted up. Afterwards sent out ALTCRQ */
	L2CONF_S_WAIT_FOR_TC_SESSIONS,
	/* Waiting for ALTCRP */
	L2CONF_S_WAIT_FOR_ALTCRP,
	/* Wait until all l2tp session altcr setted up */
	L2CONF_S_WAIT_FOR_ALTC_SESSIONS,
	/* Established */
	L2CONF_S_ESTABLISHED
};
extern struct osmo_fsm l2tp_conf_fsm;
