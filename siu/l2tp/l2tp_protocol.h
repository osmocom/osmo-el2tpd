#pragma once

#ifndef IPPROTO_L2TP
#define IPPROTO_L2TP	115
#endif

struct l2tp_control_hdr {
	uint16_t ver;                   /* Version and more */
	uint16_t length;                /* Length field */
	uint32_t ccid;                  /* Control Connection ID */
	uint16_t Ns;                    /* Next sent */
	uint16_t Nr;                    /* Next received */
} __attribute__((packed));

#define T_BIT	0x8000
#define L_BIT	0x4000
#define S_BIT	0x0800

#define Z_BITS	0x37F8		/* Reserved bits:  We must drop anything
				   with these there */

#define VER_MASK 0x0007

struct l2tp_payload_hdr {
	uint16_t ver;                   /* Version and friends */
	uint16_t length;                /* Optional Length */
	uint16_t tid;                   /* Tunnel ID */
	uint16_t cid;                   /* Caller ID */
	uint16_t Ns;                    /* Optional next sent */
	uint16_t Nr;                    /* Optional next received */
	uint16_t o_size;                /* Optional offset size */
} __attribute__((packed));

struct l2tp_avp_hdr {
	uint16_t m_h_length;
	uint16_t vendor_id;
	uint16_t attr_type;
	uint8_t value[0];
} __attribute__((packed));


enum l2tp_vendor {
	VENDOR_IETF		= 0,
	VENDOR_ERICSSON		= 193,
};

/* RFC3931 Section 5.4 */
enum l2tp_avp_ietf {
	AVP_IETF_CTRL_MSG	= 0,
	AVP_IETF_RESULT_CODE	= 1,
	AVP_IETF_CTRL_TIE_BRK	= 5,
	AVP_IETF_AS_CTRL_CON_ID	= 6,
	AVP_IETF_HOST_NAME	= 7,
	AVP_IETF_VENDOR_NAME	= 8,
	AVP_IETF_RX_WIN_SIZE	= 10,
	AVP_IETF_SER_NUMBER	= 15,
	AVP_IETF_PHYS_CHAN_ID	= 25,
	AVP_IETF_CIRC_ERRORS	= 34,
	AVP_IETF_MSG_DIGEST	= 59,
	AVP_IETF_ROUTER_ID	= 60,
	AVP_IETF_PW_CAP_LIST	= 62,
	AVP_IETF_LOC_SESS_ID	= 63,
	AVP_IETF_REM_SESS_ID	= 64,
	AVP_IETF_AS_COOKIE	= 65,
	AVP_IETF_REMOTE_END	= 66,
	AVP_IETF_PW_TYPE	= 68,
	AVP_IETF_L2_SPEC_SUBL	= 69,
	AVP_IETF_DATA_SEQUENCING= 70,
	AVP_IETF_CIRC_STATUS	= 71,
	AVP_IETF_PREF_LANG	= 72,
	AVP_IETF_AUTH_NONCE	= 73,
	AVP_IETF_TX_CONN_SPEED	= 74,
	AVP_IETF_RX_CONN_SPEED	= 75,
	AVP_IETF_RAND_VECT	= 36,
};

enum l2tp_avp_ericsson {
	AVP_ERIC_CTRL_MSG	= 0,
	AVP_ERIC_TRANSP_CFG	= 1,
	AVP_ERIC_PROTO_VER	= 3,
	AVP_ERIC_CONN_TYPE	= 4,
	AVP_ERIC_CRC_ENABLED	= 5,
	AVP_ERIC_STN_NAME	= 6,
	AVP_ERIC_ABIS_LO_MODE	= 7,
	AVP_ERIC_TEI_TO_SC_MAP	= 8,
};

/* RFC3931 Section 3.1 */
enum l2tp_ietf_ctrlmsg {
	/* Control Connection Management */
	IETF_CTRLMSG_SCCRQ	= 1,
	IETF_CTRLMSG_SCCRP	= 2,
	IETF_CTRLMSG_SCCCN	= 3,
	IETF_CTRLMSG_STOPCCN	= 4,
	IETF_CTRLMSG_HELLO	= 6,
	IETF_CTRLMSG_ACK	= 20,
	/* Call Management */
	IETF_CTRLMSG_OCRQ	= 7,
	IETF_CTRLMSG_OCRP	= 8,
	IETF_CTRLMSG_OCCN	= 9,
	IETF_CTRLMSG_ICRQ	= 10,
	IETF_CTRLMSG_ICRP	= 11,
	IETF_CTRLMSG_ICCN	= 12,
	IETF_CTRLMSG_CDN	= 14,
	/* Error Reporting */
	IETF_CTRLMSG_WEN	= 15,
	/* Lnk Status Change */
	IETF_CTRLMSG_SLI	= 16,
};

enum l2tp_eric_ctrlmsg {
	ERIC_CTRLMSG_TCN	= 0,
	ERIC_CTRLMSG_PN		= 1,
	ERIC_CTRLMSG_TCRQ	= 2,
	ERIC_CTRLMSG_TCRP	= 3,
	ERIC_CTRLMSG_ALTCRQ	= 4,
	ERIC_CTRLMSG_ALTCRP	= 5,
	ERIC_CTRLMSG_LCCSN	= 6,
};
