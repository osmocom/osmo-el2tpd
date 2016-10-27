#pragma once

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
	/* Received Transport configuration Reply */
	L2CC_E_RX_TCRP,
	/* Received Abis Lower Transport configuration Reply */
	L2CC_E_RX_ALTCRP,
	/* Received a HELLO / Keepalive */
	L2CC_E_RX_HELLO,
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

enum l2tpd_ctrl_con_state {
	/* Before we receive SCCRQ*/
	L2CC_S_INIT,
	/* After we sent SCCRP, waiting for SCCCN */
	L2CC_S_WAIT_CTL_CONN,
	/* Control Conncetion is established */
	L2CC_S_ESTABLISHED,
	/* After we sent a TCRQ, waiting for TCRP */
	L2CC_S_WAIT_FOR_TCRP,
	/* After we sent a ALTTCRQ, waiting for ALTCRP */
	L2CC_S_WAIT_FOR_ALTCRP,
	/* We configured the SIU to start sessions */
	L2CC_S_ESTABLISHED_CONFIGURED
};

/* ICRQ recipient */
enum l2tpd_in_call_state {
	/* Waiting for ICRQ */
	L2IC_S_INIT,
	/* Waiting for ICCN */
	L2IC_S_WAIT_CONN,
	L2IC_S_ESTABLISHED,
};

extern struct osmo_fsm l2tp_ic_fsm;
extern struct osmo_fsm l2tp_cc_fsm;
