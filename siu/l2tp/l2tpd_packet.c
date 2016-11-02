#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <arpa/inet.h>

#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/fsm.h>

#include "l2tp_protocol.h"
#include "l2tpd.h"
#include "l2tpd_data.h"
#include "l2tpd_fsm.h"
#include "crc32.h"

/***********************************************************************
 * AVP Parser / Encoder
 ***********************************************************************/

/* a parsed representation of an L2TP AVP */
struct avp_parsed {
	uint16_t vendor_id;
	uint16_t type;
	uint16_t data_len;
	uint8_t m:1,
		h:1;
	uint8_t *data;
};

/* parse single AVP at msg->data + offset and return the new offset */
static int msgb_avp_parse(struct avp_parsed *ap, struct msgb *msg, int offset)
{
	uint32_t msgb_left = msgb_length(msg) - offset;
	struct l2tp_avp_hdr *ah = (struct l2tp_avp_hdr *) (msgb_data(msg) + offset);
	uint16_t avp_len;

	if (sizeof(*ah) > msgb_left) {
		LOGP(DL2TP, LOGL_NOTICE, "AVP Hdr beyond end of msgb\n");
		return -1;
	}
	avp_len = ntohs(ah->m_h_length) & 0x3ff;
	if (avp_len < 6) {
		LOGP(DL2TP, LOGL_NOTICE, "AVP Parse: AVP len < 6\n");
		return -1;
	}
	if (avp_len > msgb_left) {
		LOGP(DL2TP, LOGL_NOTICE, "AVP Data beyond end of msgb\n");
		return -1;
	}

	ap->vendor_id = ntohs(ah->vendor_id);
	ap->type = ntohs(ah->attr_type);
	ap->data_len = avp_len - sizeof(*ah);
	ap->data = ah->value;
	ap->m = !!(ah->m_h_length & 0x8000);
	ap->h = !!(ah->m_h_length & 0x4000);

	return offset + avp_len;
}

struct avps_parsed {
	unsigned int num_avp;
	struct avp_parsed avp[64];
};

static int msgb_avps_parse(struct avps_parsed *avps, struct msgb *msg, int offset)
{
	memset(avps, 0, sizeof(*avps));

	while (msgb_length(msg) - offset > 0) {
		struct avp_parsed *avp = &avps->avp[avps->num_avp++];
		int rc = msgb_avp_parse(avp, msg, offset);
		if (rc < 0)
			return rc;
		else
			offset = rc;
	}
	return avps->num_avp;
}

static struct avp_parsed *
avps_parsed_find(struct avps_parsed *avps, uint16_t vendor_id, uint16_t type)
{
	unsigned int i;

	for (i = 0; i < avps->num_avp; i++) {
		struct avp_parsed *avp = &avps->avp[i];
		if (avp->vendor_id == vendor_id && avp->type == type)
			return avp;
	}
	return NULL;
}

static uint8_t *avpp_val(struct avps_parsed *avps, uint16_t vendor_id, uint16_t type)
{
	struct avp_parsed *avp = avps_parsed_find(avps, vendor_id, type);
	if (!avp)
		return NULL;
	return avp->data;
}

static int avpp_len(struct avps_parsed *avps, uint16_t vendor_id, uint16_t type)
{
	struct avp_parsed *avp = avps_parsed_find(avps, vendor_id, type);
	if (!avp)
		return 0;
	return avp->data_len;
}

int avpp_val_u32(struct avps_parsed *avps, uint16_t vendor_id, uint16_t type,
		 uint32_t *u32)
{
	struct avp_parsed *avp = avps_parsed_find(avps, vendor_id, type);
	if (!avp)
		return -ENODEV;
	if (avp->data_len < sizeof(*u32))
		return -EINVAL;

	*u32 = *((uint32_t *)avp->data);
	*u32 = htonl(*u32);
	return 0;
}

int avpp_val_u16(struct avps_parsed *avps, uint16_t vendor_id, uint16_t type,
		 uint16_t *u16)
{
	struct avp_parsed *avp = avps_parsed_find(avps, vendor_id, type);
	if (!avp)
		return -ENODEV;
	if (avp->data_len < sizeof(*u16))
		return -EINVAL;

	*u16 = *((uint16_t *)avp->data);
	*u16 = htons(*u16);
	return 0;
}

int avpp_val_u8(struct avps_parsed *avps, uint16_t vendor_id, uint16_t type,
		 uint8_t *u8)
{
	struct avp_parsed *avp = avps_parsed_find(avps, vendor_id, type);
	if (!avp)
		return -ENODEV;
	if (avp->data_len < sizeof(*u8))
		return -EINVAL;

	*u8 = *((uint8_t *)avp->data);
	return 0;
}

/* store an AVP at the end of the msg */
static int msgb_avp_put(struct msgb *msg, uint16_t vendor_id, uint16_t type,
			const uint8_t *data, uint16_t data_len, bool m_flag)
{
	uint8_t *out;

	if (data_len > 0x3ff - 6) {
		LOGP(DL2TP, LOGL_ERROR, "Data too long for AVP\n");
		return -1;
	}

	msgb_put_u16(msg, ((data_len + 6) & 0x3ff) | (m_flag ? 0x8000 : 0));
	msgb_put_u16(msg, vendor_id);
	msgb_put_u16(msg, type);
	out = msgb_put(msg, data_len);
	memcpy(out, data, data_len);

	return 6 + data_len;
}

/* store an uint8_t value AVP */
static int msgb_avp_put_u8(struct msgb *msg, uint16_t vendor, uint16_t avp_type,
			   uint8_t val, bool m_flag)
{
	return msgb_avp_put(msg, vendor, avp_type, &val, 1, m_flag);
}

/* store an uint16_t value AVP */
static int msgb_avp_put_u16(struct msgb *msg, uint16_t vendor, uint16_t avp_type,
			    uint16_t val, bool m_flag)
{
	val = htons(val);
	return msgb_avp_put(msg, vendor, avp_type, (uint8_t *)&val, 2, m_flag);
}

/* store an uint32_t value AVP */
static int msgb_avp_put_u32(struct msgb *msg, uint16_t vendor, uint16_t avp_type,
			    uint32_t val, bool m_flag)
{
	val = htonl(val);
	return msgb_avp_put(msg, vendor, avp_type, (uint8_t *)&val, 4, m_flag);
}

/* store a 'message type' AVP */
static int msgb_avp_put_msgt(struct msgb *msg, uint16_t vendor, uint16_t msg_type)
{
	return msgb_avp_put_u16(msg, vendor, AVP_IETF_CTRL_MSG, msg_type, true);
}


/***********************************************************************
 * Message utilities
 ***********************************************************************/

/* swap all fields of the l2tp_control header structure */
static void l2tp_hdr_swap(struct l2tp_control_hdr *ch)
{
	ch->ver = ntohs(ch->ver);
	ch->length = ntohs(ch->length);
	ch->ccid = ntohl(ch->ccid);
	ch->Ns = ntohs(ch->Ns);
	ch->Nr = ntohs(ch->Nr);
}

struct msgb *l2tp_msgb_alloc(void)
{
	struct msgb *msg = msgb_alloc_headroom(1600, 100, "L2TP");
	if (msg)
		msg->l2h = msg->data;
	return msg;
}

static int msgb_avp_put_digest(struct msgb *msg)
{
	/* we simply put a zero-initialized AVP for now and update when
	 * trnasmitting */
	const uint8_t digest_zero[17] = { 0, };
	return msgb_avp_put(msg, VENDOR_IETF, AVP_IETF_MSG_DIGEST,
				digest_zero, sizeof(digest_zero), true);
}

/* E/// L2TP seems to use a static, constant HMAC key */
static const uint8_t digest_key[] = {
	0x7b, 0x60, 0x85, 0xfb, 0xf4, 0x59, 0x33, 0x67,
	0x0a, 0xbc, 0xb0, 0x7a, 0x27, 0xfc, 0xea, 0x5e
};

/* update the message digest inside the AVP of a message */
static int digest_avp_update(struct msgb *msg)
{
	struct l2tp_control_hdr *l2h = (struct l2tp_control_hdr *) msgb_data(msg);
	struct l2tp_avp_hdr *ah = (struct l2tp_avp_hdr *) ((uint8_t *)l2h + sizeof(*l2h));
	uint8_t *hmac_res;
	unsigned int len = ntohs(l2h->length);

	/* Digest AVP header is guaranteed to be the second AVP in a
	 * control message.  First AVP is message type AVP with overall
	 * length of 8 bytes */
	ah = (struct l2tp_avp_hdr *) ((uint8_t *) ah + 8);

	if (ntohs(ah->attr_type) != AVP_IETF_MSG_DIGEST ||
	    ntohs(ah->vendor_id) != VENDOR_IETF ||
	    (ntohs(ah->m_h_length) & 0x3FF) != 23) {
		LOGP(DL2TP, LOGL_ERROR, "Missing Digest AVP, cannot update\n");
		return -1;
	}

	if (len > msgb_length(msg)) {
		/* FIXME: improve log message */
		LOGP(DL2TP, LOGL_ERROR, "invalid length");
		return -1;
	}

	DEBUGP(DL2TP, "Tx Message before digest: %s\n", msgb_hexdump(msg));
	/* RFC says HMAC_Hash(shared_key, local_nonce + remote_nonce + control_message),
	 * but ericsson is doning something different without any
	 * local/remote nonce? */
	hmac_res = HMAC(EVP_md5(), digest_key, sizeof(digest_key),
			(const uint8_t *)l2h, len, NULL, NULL);
	memcpy(ah->value + 1, hmac_res, 16);
	DEBUGP(DL2TP, "Tx Message with digest: %s\n", msgb_hexdump(msg));

	return 0;
}

static int l2tp_msgb_tx(struct msgb *msg, int not_ack)
{
	struct l2tpd_connection *l2c = msg->dst;
	struct l2tp_control_hdr *l2h;
	int ret;
	uint32_t *session_id;

	/* first prepend the L2TP control header */
	l2h = (struct l2tp_control_hdr *) msgb_push(msg, sizeof(*l2h));
	l2h->ver = htons(T_BIT|L_BIT|S_BIT| 0x3);
	l2h->length = htons(msgb_length(msg));
	l2h->ccid = htonl(l2c->remote.ccid);
	l2h->Nr = htons(l2c->next_rx_seq_nr);
	/* only acks dont increase seq */
	if (not_ack)
		l2h->Ns = htons(l2c->next_tx_seq_nr++);
	else
		l2h->Ns = htons(l2c->next_tx_seq_nr);

	/* then insert/patch the message digest AVP */
	digest_avp_update(msg);

	/* push session id */
	session_id = (uint32_t *) msgb_push(msg, 4);
	*session_id = 0;

	/* FIXME: put in the queue for reliable re-transmission */

	ret = sendto(l2i->l2tp_ofd.fd, msgb_data(msg), msgb_length(msg), 0, &l2c->remote.ss, sizeof(l2c->remote.ss));

	msgb_free(msg);
	if (ret < 0)
		return ret;
	return 0;
}

int l2tp_tx_data(struct msgb *msg)
{
	struct l2tp_data_hdr *hdr;
	struct l2tpd_session *l2s = msg->dst;
	struct l2tpd_connection *l2c = l2s->connection;
	int ret;
	uint32_t crc;

	hdr = (struct l2tp_data_hdr *) msgb_push(msg, sizeof(*hdr));
	hdr->session_id = htonl(l2s->r_sess_id);
	hdr->sequence_id = htonl(l2s->next_tx_seq_nr++ | L2TP_DATA_SEQ_BIT);
	hdr->crc = 0;

	crc = crc32(0x0, msgb_data(msg), (size_t) msgb_length(msg));
	hdr->crc = htonl(crc);

	ret = sendto(l2i->l2tp_ofd.fd, msgb_data(msg), msgb_length(msg), 0, &l2c->remote.ss, sizeof(l2c->remote.ss));
	if (ret < 0)
		return ret;
	return 0;
}

/***********************************************************************
 * IETF specified messages
 ***********************************************************************/

int l2tp_tx_scc_rp(struct l2tpd_connection *l2c)
{
	struct msgb *msg = l2tp_msgb_alloc();
	const uint8_t eric_ver3_only[12] = { 0,0,0,3,  0,0,0,0, 0,0,0,0 };
	const uint8_t host_name[3] = { 'B', 'S', 'C' };
	const uint8_t vendor_name[8] = { 'E', 'r', 'i', 'c', 's', 's', 'o', 'n' };
	struct in_addr router_id;
	inet_aton("172.30.42.3", &router_id);

	msgb_avp_put_msgt(msg, VENDOR_IETF, IETF_CTRLMSG_SCCRP);
	msgb_avp_put_digest(msg);
	msgb_avp_put_u32(msg, VENDOR_IETF, AVP_IETF_AS_CTRL_CON_ID,
			 l2c->local.ccid, true);
	msgb_avp_put(msg, VENDOR_ERICSSON, AVP_ERIC_PROTO_VER,
		     eric_ver3_only, sizeof(eric_ver3_only), true);
	msgb_avp_put(msg, VENDOR_IETF, AVP_IETF_HOST_NAME,
			host_name, sizeof(host_name), false);
	msgb_avp_put(msg, VENDOR_IETF, AVP_IETF_VENDOR_NAME,
			vendor_name, sizeof(vendor_name), false);
	msgb_avp_put(msg, VENDOR_IETF, AVP_IETF_ROUTER_ID,
		     (uint8_t *)&router_id.s_addr, sizeof(router_id.s_addr), false);
	msgb_avp_put_u16(msg, VENDOR_IETF, AVP_IETF_PW_CAP_LIST,
			 0x0006, true);

	msg->dst = l2c;
	return l2tp_msgb_tx(msg, 1);
}

int l2tp_tx_stop_ccn(struct l2tpd_connection *l2c)
{
	struct msgb *msg = l2tp_msgb_alloc();
	/* FIXME: use pointer instead of this call */

	msgb_avp_put_msgt(msg, VENDOR_IETF, IETF_CTRLMSG_STOPCCN);
	msgb_avp_put_digest(msg);
	msgb_avp_put_u16(msg, VENDOR_IETF, AVP_IETF_RESULT_CODE, 0x1, 1);

	msg->dst = l2c;
	return l2tp_msgb_tx(msg, 1);
}

int l2tp_tx_stop_ccn_msg(struct msgb *old)
{
	struct msgb *msg = l2tp_msgb_alloc();
	struct l2tpd_connection l2c;
	memset(&l2c, 0x0, sizeof(l2c));

	struct l2tp_control_hdr *ch = (struct l2tp_control_hdr *) msgb_data(old);

	memcpy(&l2c.remote.ss, old->dst, sizeof(struct sockaddr));
	l2c.next_tx_seq_nr = ch->Nr;
	l2c.next_rx_seq_nr = ch->Ns + 1;
	l2c.remote.ccid = ch->ccid;
	/* FIXME: use pointer instead of this call */

	msgb_avp_put_msgt(msg, VENDOR_IETF, IETF_CTRLMSG_STOPCCN);
	msgb_avp_put_digest(msg);

	msg->dst = &l2c;
	return l2tp_msgb_tx(msg, 1);
}

int l2tp_tx_tc_rq(struct l2tpd_connection *l2c)
{
    struct msgb *msg = l2tp_msgb_alloc();
    const uint8_t tcg[] = {
        0x03, 0xe8, /* overload threashold */
        0x03, /* number of transport groups */

        /* first transport group */
        0x11, /* tc group id */
        0x02, /* number of sapis */
	00, 62, /* SAPIs */
	172, 30, 42, 3, /* IP */
        0x2e, 0x01, 0x5, 0x1, 0x2c, /* dscp, crc32, bundling timeout, max packet size */

        /* second transport group */
        0x06, /* tc group id */
        0x02, /* number of sapis */
	10, 11, /* SAPIs */
	172, 30, 42, 3, /* IP */
        0x08, 0x01, 0x5, 0x1, 0x2c, /* dscp, crc32, bundling timeout, max packet size */

        /* third transport group */
        0x08, /* tc group id */
        0x01, /* number of sapis */
	12, /* SAPIs */
	172, 30, 42, 3, /* IP */
        0x22, 0x01, 0x5, 0x1, 0x2c, /* dscp, crc32, bundling timeout, max packet size */
    };

    msgb_avp_put_msgt(msg, VENDOR_ERICSSON, ERIC_CTRLMSG_TCRQ);
    msgb_avp_put_digest(msg);
    msgb_avp_put(msg, VENDOR_ERICSSON, AVP_ERIC_TRANSP_CFG,
	    tcg, sizeof(tcg), true);

    msg->dst = l2c;
    return l2tp_msgb_tx(msg, 1);
}

int l2tp_tx_altc_rq_timeslot(struct l2tpd_connection *l2c)
{
	struct msgb *msg = l2tp_msgb_alloc();

	msgb_avp_put_msgt(msg, VENDOR_ERICSSON, ERIC_CTRLMSG_ALTCRQ);
	msgb_avp_put_digest(msg);
	msgb_avp_put_u8(msg, VENDOR_ERICSSON, AVP_ERIC_ABIS_LO_MODE,
			 0x0, true); /* SingleTimeslot */

	msg->dst = l2c;
	return l2tp_msgb_tx(msg, 1);
}

int l2tp_tx_altc_rq_superchannel(struct l2tpd_connection *l2c)
{
	struct msgb *msg = l2tp_msgb_alloc();
	const uint8_t tcsc[] = {
		2, /* number of transport config bundling group */
		1, 1, 0x0, /* TEI from 1 to 1 to SC 0 */
		62, 62, 0x0}; /* TEI from 62 to 62 to SC 0 */

	msgb_avp_put_msgt(msg, VENDOR_ERICSSON, ERIC_CTRLMSG_ALTCRQ);
	msgb_avp_put_digest(msg);
	msgb_avp_put_u8(msg, VENDOR_ERICSSON, AVP_ERIC_ABIS_LO_MODE,
			 0x1, true); /* Superchannel */
	msgb_avp_put(msg, VENDOR_ERICSSON, AVP_ERIC_TEI_TO_SC_MAP,
			tcsc, sizeof(tcsc), true);

	msg->dst = l2c;
	return l2tp_msgb_tx(msg, 1);
}

int l2tp_tx_ic_rp(struct l2tpd_session *l2s)
{
	struct msgb *msg = l2tp_msgb_alloc();
	struct l2tpd_connection *l2c = l2s->connection;

	msgb_avp_put_msgt(msg, VENDOR_IETF, IETF_CTRLMSG_ICRP);
	msgb_avp_put_digest(msg);
	msgb_avp_put_u32(msg, VENDOR_IETF, AVP_IETF_LOC_SESS_ID,
			 l2s->l_sess_id, true);
	msgb_avp_put_u32(msg, VENDOR_IETF, AVP_IETF_REM_SESS_ID,
			 l2s->r_sess_id, true);
	/* Circuit type: existing; Circuit status: up */
	msgb_avp_put_u16(msg, VENDOR_IETF, AVP_IETF_CIRC_STATUS,
			 0x0001, true);
	/* Default L2 specific sublayer present */
	msgb_avp_put_u16(msg, VENDOR_IETF, AVP_IETF_L2_SPEC_SUBL,
			 0x0001, true);
	/* All incoming data packets require sequencing */
	msgb_avp_put_u16(msg, VENDOR_IETF, AVP_IETF_DATA_SEQUENCING,
			 0x0002, true);

	msg->dst = l2c;
	return l2tp_msgb_tx(msg, 1);
}

int l2tp_tx_ack(struct l2tpd_connection *l2c)
{
	struct msgb *msg = l2tp_msgb_alloc();
	/* FIXME: use pointer instead of this call */

	msgb_avp_put_msgt(msg, VENDOR_IETF, IETF_CTRLMSG_ACK);
	msgb_avp_put_digest(msg);

	msg->dst = l2c;
	return l2tp_msgb_tx(msg, 0);
}

int l2tp_tx_hello(struct l2tpd_session *l2s)
{
	struct msgb *msg = l2tp_msgb_alloc();
	/* FIXME: use pointer instead of this call */
	struct l2tpd_connection *l2c = l2tpd_cc_find_by_l_cc_id(l2i, l2s->l_sess_id);

	msgb_avp_put_msgt(msg, VENDOR_IETF, IETF_CTRLMSG_HELLO);
	msgb_avp_put_digest(msg);

	msg->dst = l2c;
	return l2tp_msgb_tx(msg, 1);
}

/* Incoming "Start Control-Connection Request" from SIU */
static int rx_scc_rq(struct l2tpd_connection *l2c, struct msgb *msg, struct avps_parsed *ap)
{
	struct l2tp_control_hdr *ch = (struct l2tp_control_hdr *) msgb_data(msg);
	struct sockaddr *sockaddr = msg->dst;
	char *host_name = NULL;
	uint16_t pw;

	/* Abort if Pseudowire capability doesn't include 6(HDLC) */
	if (avpp_val_u16(ap, VENDOR_IETF, AVP_IETF_PW_CAP_LIST, &pw) < 0 ||
	    pw != 0x0006) {
		LOGP(DL2TP, LOGL_ERROR, "Pseudowire != HDLC\n");
		return -1;
	}

	if (ch->ccid == 0) {
		uint32_t remote_ccid, router_id;
		l2c = l2tpd_cc_alloc(l2i);
		/* Get Assigned CCID and store in l2cc->remote.ccid */
		avpp_val_u32(ap, VENDOR_IETF, AVP_IETF_AS_CTRL_CON_ID,
			     &remote_ccid);
		l2c->remote.ccid = remote_ccid;
		/* Router ID AVP */
		if (avpp_val_u32(ap, VENDOR_IETF, AVP_IETF_ROUTER_ID,
				 &router_id))
			l2c->remote.router_id = router_id;
		/* Host Name AVP */
		host_name = (char *) avpp_val(ap, VENDOR_IETF, AVP_IETF_HOST_NAME);
		if (host_name)
			l2c->remote.host_name = talloc_strdup(l2c, host_name);
		memcpy(&l2c->remote.ss, sockaddr, sizeof(*sockaddr));
		l2c->next_rx_seq_nr = 1;
		LOGP(DL2TP, LOGL_INFO, "Allocated CC: local %d remote %d\n", l2c->local.ccid, l2c->remote.ccid);
	} else {
		LOGP(DL2TP, LOGL_ERROR, "Received a SCCRQ with control id != 0: %d\n", ch->ccid);
		return -1;
	}

	osmo_fsm_inst_dispatch(l2c->fsm, L2CC_E_RX_SCCRQ, msg);
	return 0;
}

/* Incoming "Start Control-Connection Connected" from SIU */
static int rx_scc_cn(struct l2tpd_connection *l2cc, struct msgb *msg, struct avps_parsed *ap)
{
	if (!l2cc)
		return -1;

	osmo_fsm_inst_dispatch(l2cc->fsm, L2CC_E_RX_SCCCN, msg);
	/* FIXME: Send TCRQ and ALTCRQ */
	return 0;
}

/* Incoming "Stop Control-Connection Notificiation" from SIU */
static int rx_stop_ccn(struct l2tpd_connection *l2cc, struct msgb *msg, struct avps_parsed *ap)
{
	if (!l2cc)
		return -1;

	osmo_fsm_inst_dispatch(l2cc->fsm, L2CC_E_RX_STOP_CCN, msg);
	return 0;
}

/* Incoming Keepalive / Hello from SIU */
static int rx_hello(struct l2tpd_connection *l2cc, struct msgb *msg, struct avps_parsed *ap)
{
	if (!l2cc)
		return -1;

	osmo_fsm_inst_dispatch(l2cc->fsm, L2CC_E_RX_HELLO, msg);
	return 0;
}


/* Incoming "Incoming Call Request" from SIU */
static int rx_ic_rq(struct l2tpd_connection *l2cc, struct msgb *msg, struct avps_parsed *ap)
{
	struct l2tpd_session *l2s;
	uint32_t r_sess_id = 0;
	uint32_t l_sess_id = 0;

	if (!l2cc)
		return -1;
	if (avpp_val_u32(ap, VENDOR_IETF, AVP_IETF_REM_SESS_ID, &r_sess_id)) {
		LOGP(DL2TP, LOGL_ERROR, "ccid %d: Missing AVP REM_SESS_ID\n",
		     l2cc->local.ccid);
		return -1;
	}
	if (avpp_val_u32(ap, VENDOR_IETF, AVP_IETF_LOC_SESS_ID, &l_sess_id)) {
		LOGP(DL2TP, LOGL_ERROR, "ccid %d: Missing AVP LOC_SESS_ID\n",
		     l2cc->local.ccid);
		return -1;
	}

	if (r_sess_id == 0) {
		l2s = l2tpd_sess_alloc(l2cc);
		l2s->r_sess_id = l_sess_id;
		avpp_val_u16(ap, VENDOR_IETF, AVP_IETF_PW_TYPE, &l2s->pw_type);
		avpp_val_u8(ap, VENDOR_IETF, AVP_IETF_REMOTE_END, &l2s->remote_end_id);
	} else {
		LOGP(DL2TP, LOGL_NOTICE, "ccid %d: Received rx_ic_rq for already known session %u\n",
		     l2cc->local.ccid, r_sess_id);
		l2s = l2tpd_sess_find_by_l_s_id(l2cc, r_sess_id);
		if (!l2s) {
			LOGP(DL2TP, LOGL_ERROR, "NoSession found for %u\n",
				r_sess_id);
			/* FIXME: send error packet */
			return -1;
		}
	}

	osmo_fsm_inst_dispatch(l2s->fsm, L2IC_E_RX_ICRQ, msg);
	return 0;
}

static struct l2tpd_session *
get_session_by_msg(struct l2tpd_connection *l2cc, struct msgb *msg,
			       struct avps_parsed *ap)
{
	struct l2tpd_session *l2s;
	uint32_t l_sess_id;
	uint32_t r_sess_id;

	if (avpp_val_u32(ap, VENDOR_IETF, AVP_IETF_REM_SESS_ID, &r_sess_id)) {
		LOGP(DL2TP, LOGL_ERROR, "ccid %d: Missing AVP REM_SESS_ID\n",
		     l2cc->local.ccid);
		return NULL;
	}
	if (avpp_val_u32(ap, VENDOR_IETF, AVP_IETF_LOC_SESS_ID, &l_sess_id)) {
		LOGP(DL2TP, LOGL_ERROR, "ccid %d: Missing AVP LOC_SESS_ID\n",
		     l2cc->local.ccid);
		return NULL;
	}

	l2s = l2tpd_sess_find_by_l_s_id(l2cc, r_sess_id);
	if (!l2s) {
		LOGP(DL2TP, LOGL_ERROR, "ccid %d: Can not find session %d\n",
		     l2cc->local.ccid, r_sess_id);
		return NULL;
	}

	if (l2s->r_sess_id != l_sess_id) {
		LOGP(DL2TP, LOGL_ERROR, "ccid %d: Packet remote session id %d differs from known %d\n",
		     l2cc->local.ccid, l_sess_id, l2s->r_sess_id);
		return NULL;
	}

	return l2s;
}

/* Incoming "Incoming Call Connected" from SIU */
static int rx_ic_cn(struct l2tpd_connection *l2cc, struct msgb *msg, struct avps_parsed *ap)
{
	struct l2tpd_session *l2s;

	if (!l2cc)
		return -1;

	l2s = get_session_by_msg(l2cc, msg, ap);
	if (!l2s) {
		return -1;
	}

	osmo_fsm_inst_dispatch(l2s->fsm, L2IC_E_RX_ICCN, msg);
	return 0;
}

/* Incoming "Incoming Call Connected" from SIU */
static int rx_cdn(struct l2tpd_connection *l2cc, struct msgb *msg, struct avps_parsed *ap)
{
	if (!l2cc)
		return -1;

	osmo_fsm_inst_dispatch(l2cc->fsm, L2IC_E_RX_CDN, msg);
	return 0;
}

/* Receive an IETF specified control message */
static int l2tp_rcvmsg_control_ietf(struct l2tpd_connection *l2c,
				    struct msgb *msg, struct avps_parsed *ap,
				    uint16_t msg_type)
{
	switch (msg_type) {
	case IETF_CTRLMSG_SCCRQ:
		return rx_scc_rq(l2c, msg, ap);
	case IETF_CTRLMSG_SCCCN:
		return rx_scc_cn(l2c, msg, ap);
	case IETF_CTRLMSG_STOPCCN:
		return rx_stop_ccn(l2c, msg, ap);
	case IETF_CTRLMSG_ICRQ:
		return rx_ic_rq(l2c, msg, ap);
	case IETF_CTRLMSG_ICCN:
		return rx_ic_cn(l2c, msg, ap);
	case IETF_CTRLMSG_CDN:
		return rx_cdn(l2c, msg, ap);
	case IETF_CTRLMSG_HELLO:
		return rx_hello(l2c, msg, ap);
	default:
		LOGP(DL2TP, LOGL_ERROR, "Unknown/Unhandled IETF Control "
			"Message Type 0x%04x\n", msg_type);
		return -1;
	}
}

/***********************************************************************
 * Ericsson specific messages
 ***********************************************************************/

static int rx_eri_tcrp(struct l2tpd_connection *l2c, struct msgb *msg, struct avps_parsed *ap)
{
	uint16_t avp_result = 0;

	if (!l2c)
		return -1;

	if (avpp_val_u16(ap, VENDOR_IETF, AVP_IETF_RESULT_CODE, &avp_result)) {
		LOGP(DL2TP, LOGL_ERROR, "TXRP doesnt contain a result code. Aborting control connection.\n");
		osmo_fsm_inst_dispatch(l2c->fsm, L2CC_E_LOCAL_CLOSE_REQ, msg);
	}

	if (avp_result) {
		LOGP(DL2TP, LOGL_ERROR, "TXRP returned result code %d instead of 0. Aborting control connection.\n",
		     avp_result);
		/* FIXME: result message */
		osmo_fsm_inst_dispatch(l2c->fsm, L2CC_E_LOCAL_CLOSE_REQ, msg);
	}
	osmo_fsm_inst_dispatch(l2c->conf_fsm, L2CONF_E_RX_TCRP, msg);
	return 0;
}

static int rx_eri_altcrp(struct l2tpd_connection *l2c, struct msgb *msg, struct avps_parsed *ap)
{
	uint16_t avp_result = 0;

	if (!l2c)
		return -1;

	if (avpp_val_u16(ap, VENDOR_IETF, AVP_IETF_RESULT_CODE, &avp_result)) {
		LOGP(DL2TP, LOGL_ERROR, "ALTXRP doesnt contain a result code. Aborting control connection.\n");
		osmo_fsm_inst_dispatch(l2c->fsm, L2CC_E_LOCAL_CLOSE_REQ, msg);
	}

	if (avp_result) {
		LOGP(DL2TP, LOGL_ERROR, "ALTXRP returned result code %d instead of 0. Aborting control connection.\n",
		     avp_result);
		/* FIXME: result message */
		osmo_fsm_inst_dispatch(l2c->fsm, L2CC_E_LOCAL_CLOSE_REQ, msg);
	}
	osmo_fsm_inst_dispatch(l2c->conf_fsm, L2CONF_E_RX_ALTCRP, msg);
	return 0;
}

/* Receive an Ericsson specific control message */
static int l2tp_rcvmsg_control_ericsson(struct l2tpd_connection *l2c,
					struct msgb *msg, struct avps_parsed *ap,
					uint16_t msg_type)
{
	LOGP(DL2TP, LOGL_ERROR, "Rx: ericsson msg_type 0x%04x\n", msg_type);
	switch (msg_type) {
	case ERIC_CTRLMSG_TCRP:
		return rx_eri_tcrp(l2c, msg, ap);
	case ERIC_CTRLMSG_ALTCRP:
		return rx_eri_altcrp(l2c, msg, ap);
	default:
		LOGP(DL2TP, LOGL_ERROR, "Unknown/Unhandled Ericsson Control "
			"Message Type 0x%04x\n", msg_type);
		return -1;
	}
}

static int l2tp_rcvmsg_control(struct msgb *msg)
{
	struct l2tp_control_hdr *ch = (struct l2tp_control_hdr *) msgb_data(msg);
	struct l2tpd_connection *l2c = NULL;
	struct avps_parsed ap;
	struct avp_parsed *first_avp;
	uint16_t msg_type;
	int rc;

	l2tp_hdr_swap(ch);

	if ((ch->ver & VER_MASK) != 3) {
		LOGP(DL2TP, LOGL_ERROR, "L2TP Version != 3\n");
		return -1;
	}

	if ((ch->ver & (T_BIT|L_BIT|S_BIT)) != (T_BIT|L_BIT|S_BIT)) {
		LOGP(DL2TP, LOGL_ERROR, "L2TP Bits wrong\n");
		return -1;
	}

	if (ch->ver & Z_BITS) {
		LOGP(DL2TP, LOGL_ERROR, "L2TP Z bit must not be set\n");
		return -1;
	}

	if (msgb_l2tplen(msg) < ch->length) {
		LOGP(DL2TP, LOGL_ERROR, "L2TP message length beyond msgb\n");
		return -1;
	}

	/* Parse the first AVP an see if it is Control Message */
	rc = msgb_avps_parse(&ap, msg, sizeof(*ch));
	if (rc < 0) {
		LOGP(DL2TP, LOGL_ERROR, "Error in parsing AVPs\n");
		return rc;
	}
	if (ap.num_avp <= 0) {
		LOGP(DL2TP, LOGL_ERROR, "Not at least one AVP\n");
		return -1;
	}
	first_avp = &ap.avp[0];

	if (first_avp->data_len != 2) {
		LOGP(DL2TP, LOGL_ERROR, "Control Msg AVP length !=2: %u\n",
			first_avp->data_len);
		return -1;
	}
	msg_type = osmo_load16be(first_avp->data);

	/* FIXME: we need to get the l2c here to count the rx */
	if (ch->ccid != 0) {
		/* lookup control connection */
		l2c = l2tpd_cc_find_by_l_cc_id(l2i, ch->ccid);
		if (!l2c) {
			LOGP(DL2TP, LOGL_ERROR, "l2tp: can not find a connection for ccid %d\n", ch->ccid);
			l2tp_tx_stop_ccn_msg(msg);
			return -1;
		}

		/* FIXME: do real seq numbering. check if already received etc. */
		if (l2c->next_rx_seq_nr < (ch->Ns + 1))
			l2c->next_rx_seq_nr =  ch->Ns + 1;
		if (l2c->next_tx_seq_nr != ch->Nr)
			LOGP(DL2TP, LOGL_ERROR, "cid %d: wrong seq number received. expectd %d != recveived %d.\n", l2c->local.ccid, l2c->next_tx_seq_nr, ch->Ns);
	}

	LOGP(DL2TP, LOGL_ERROR, "Rx: l2tp vendor/type 0x%04x/0x%04x 0x%04x\n", first_avp->vendor_id, first_avp->type, msg_type);

	if (first_avp->vendor_id == VENDOR_IETF &&
	    first_avp->type == AVP_IETF_CTRL_MSG)
		return l2tp_rcvmsg_control_ietf(l2c, msg, &ap, msg_type);
	else if (first_avp->vendor_id == VENDOR_ERICSSON &&
		 first_avp->type == AVP_ERIC_CTRL_MSG)
		return l2tp_rcvmsg_control_ericsson(l2c, msg, &ap, msg_type);

	LOGP(DL2TP, LOGL_ERROR, "Unknown packet received.\n");
	return -1;
}

static int l2tp_rcvmsg_data(struct msgb *msg, bool ip_transport)
{
	DEBUGP(DL2TP, "rx data: %s\n", msgb_hexdump(msg));
	return 0;
}

int l2tp_rcvmsg(struct msgb *msg)
{
	uint32_t session = osmo_load32be(msgb_l2tph(msg));
	if (session == 0) {
		/* strip session ID and feed to control */
		msgb_pull(msg, sizeof(session));
		return l2tp_rcvmsg_control(msg);
	} else {
		LOGP(DL2TP, LOGL_ERROR, "Received session %d data.\n", session);
	}
	return -1;
}
