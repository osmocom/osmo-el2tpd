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


