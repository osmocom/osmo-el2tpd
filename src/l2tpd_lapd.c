/* Handling of Ericsson specific LAPD / EHDLC format */

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

#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "l2tp_protocol.h"

#include "l2tpd.h"
#include "l2tpd_lapd.h"
#include "l2tpd_packet.h"
#include "l2tpd_socket.h"
#include "l2tpd_logging.h"

#include "unixsocket_proto.h"

/* lapd and ehdlc differs in the first 16 bit
 * lapd saves tei, sapi, c/r bit, ea1, ea2 bit
 * ehdlc saves tei, sapi, c/r and length in a compressed way,
 * meaining tei & sapi are limited to certain values */

#define LAPD_SAPI_SHIFT 10
#define LAPD_SAPI_MASK 0xfc00
#define LAPD_TEI_SHIFT 1
#define LAPD_TEI_MASK  0x00fe
#define LAPD_CR_BIT_MASK 0x0200
#define LAPD_EA2_BIT_MASK 0x0001

#define EHDLC_CSAPI_MASK 0xe000
#define EHDLC_CSAPI_SHIFT 13
#define EHDLC_CTEI_MASK 0x1e00
#define EHDLC_CTEI_SHIFT 9
#define EHDLC_LENGTH_MASK 0x01ff

/*!
 * \brief csapi_to_sapi
 * \param csapi
 * \return sapi
 */
static int csapi_to_sapi(int csapi)
{
	switch (csapi) {
		case 0:
		case 1:
			return 0;
		case 2:
			return 10;

		case 3:
			return 11;
		case 4:
			return 12;
		case 5:
		case 6:
			return 62;
		default:
			return -1;
	}
}

/*!
 * \brief csapi_to_cr
 * \param csapi
 * \return cr bit
 */
static int csapi_to_cr(int csapi)
{
	switch (csapi) {
		case 0:
			return 0;
		case 1:
			return 1;
		case 2:
		case 3:
		case 4:
		case 5:
			return 0;
		case 6:
			return 1;
		default:
			return -1;
	}
}

/*!
 * \brief sapi_to_csapi
 * \param sapi
 * \param cr c/r bit
 * \return
 */
static int sapi_to_csapi(int sapi, int cr)
{
	switch (sapi) {
		case 0:
			return cr ? 1 : 0;
		case 10:
			return 2;
		case 11:
			return 3;
		case 12:
			return 4;
		case 62:
			return cr ? 6 : 5;
		default:
			return -1;
	}
}

static int tei_to_ctei(int tei)
{
	if (tei >= 0 && tei <= 11)
		return tei;
	else if (tei >= 60 && tei <= 63)
		return tei - 48;
	else /* invalid */
		return -1;
}

static int ctei_to_tei(int ctei)
{
	if (ctei >= 0 && ctei <= 11)
		return ctei;
	else if (ctei >= 12 && ctei <= 15)
		return ctei + 48;
	else /* invalid */
		return -1;
}

int lapd_lapd_to_ehdlc(struct l2tpd_instance *l2i, struct msgb *msg)
{
	uint16_t lapd_address = osmo_load16be(msgb_data(msg));
	uint16_t ehdlc_compressed = 0;
	int sapi = lapd_address >> LAPD_SAPI_SHIFT;
	int tei = (lapd_address & LAPD_TEI_MASK) >> LAPD_TEI_SHIFT;
	int cr = lapd_address & LAPD_CR_BIT_MASK;
	int length = msgb_length(msg);

	ehdlc_compressed |= (sapi_to_csapi(sapi, cr) <<  EHDLC_CSAPI_SHIFT) & EHDLC_CSAPI_MASK;
	ehdlc_compressed |= (tei_to_ctei(tei) <<  EHDLC_CTEI_SHIFT) & EHDLC_CTEI_MASK;
	ehdlc_compressed |= length & EHDLC_LENGTH_MASK;

	osmo_store16be(ehdlc_compressed, msgb_data(msg));

	return l2tp_tx_data(msg);
}

/*!
 * \brief lapd_ehdlc_to_lapd convert a EDHLC message to LAPD message
 *  and enqueue the message for transmit over the unix socket.
 * \param l2i
 * \param session which received the packets
 * \param msg
 * \return
 */
int lapd_ehdlc_to_lapd(struct l2tpd_instance *l2i, struct l2tpd_session *l2s, struct msgb *msg)
{
	int ret = 0;
	struct traffic_channel *channel = NULL;
	switch (l2s->remote_end_id) {
		case TC_GROUP_PGSL:
			channel = &l2i->pgsl;
			break;

		case TC_GROUP_RSL_OML:
			channel = &l2i->rsl_oml;
			break;
		case TC_GROUP_TRAU:
			channel = &l2i->trau;
			break;
	}

	if (!channel) {
		LOGP(DL2TP, LOGL_NOTICE, "eh2lapd: Can not find traffic channel for session %d\n", l2s->l_sess_id);
		return -1;
	}

	/* FIXME: do we have to sent empty packets ? */
	while (msgb_length(msg) > 2) {
		struct msgb *send_msg;
		uint16_t lapd_address = 0;
		uint16_t ehdlc_compressed = osmo_load16be(msgb_data(msg));
		int csapi = (ehdlc_compressed & EHDLC_CSAPI_MASK) >> EHDLC_CSAPI_SHIFT;
		int ctei = (ehdlc_compressed & EHDLC_CTEI_MASK) >> EHDLC_CTEI_SHIFT;
		int length = (ehdlc_compressed & EHDLC_LENGTH_MASK);

		lapd_address |= (csapi_to_sapi(csapi) << LAPD_SAPI_SHIFT) & LAPD_SAPI_MASK;
		lapd_address |= csapi_to_cr(csapi) ? LAPD_CR_BIT_MASK : 0;
		lapd_address |= (ctei_to_tei(ctei) << LAPD_TEI_SHIFT) & LAPD_TEI_MASK;
		lapd_address |= LAPD_EA2_BIT_MASK;

		osmo_store16be(lapd_address, msgb_data(msg));

		if (length > msgb_length(msg)) {
			LOGP(DL2TP, LOGL_NOTICE, "eh2lapd: Can not parse msg as ehdlc because its to short. %d > %d.\n", length, msgb_length(msg));
			return 0;
		}

		send_msg = msgb_alloc_headroom(1600, 100, "ehdlc_to_lapd");
		memcpy(msgb_data(send_msg), msgb_data(msg), length);
		msgb_pull(msg, length);
		msgb_put(send_msg, length);

		if (channel->version_control_header) {
			msgb_push_u8(send_msg, UNIXSOCKET_PROTO_DATA);
			msgb_push_u8(send_msg, UNIXSOCKET_PROTO_VERSION);
		}

		ret = l2tp_socket_enqueue(&channel->state, send_msg);
		if (ret < 0) {
			/* queue is full or other error, we have to free send_msg on our own.*/
			msgb_free(send_msg);
		}
	}

	if (msgb_length(msg) > 0)
		LOGP(DL2TP, LOGL_NOTICE, "eh2lapd: bytes leftover after parsing %d.\n", msgb_length(msg));

	return 0;
}

/*!
 * \brief lapd_process_version_header parse the extra version controldata header
 * if the header is valid and contains data -> pass to siu (return 0)
 * if header is invalid or contains control data -> dont passed to siu (return 1)
 * \param l2i
 * \param msg
 * \return 0 if should passthrough to the siu, 1 if processed or invalid
 */
int lapd_process_version_header(struct l2tpd_instance *l2i, struct msgb *msg)
{
	struct l2tpd_session *l2s = msg->dst;
	uint8_t version = 0;
	uint8_t datacontrol = 0;

	/* msgb must contain version + controldata byte */
	if (msgb_length(msg) < 2) {
		/* invalid packet. drop it */
		return 1;
	}

	version = msgb_pull_u8(msg);
	datacontrol = msgb_pull_u8(msg);

	if (version != UNIXSOCKET_PROTO_VERSION) {
		LOGP(DL2TP, LOGL_ERROR, "Invalid packet version received: %d. Expected %d.\n",
		     version, UNIXSOCKET_PROTO_VERSION);
		return 1;
	}

	switch(datacontrol) {
	case UNIXSOCKET_PROTO_DATA:
		/* pass it to siu */
		msg->l2h = msg->data;
		return 0;
	case UNIXSOCKET_PROTO_CONTROL:
		break; /* handle later */
	default:
		LOGP(DL2TP, LOGL_ERROR, "Invalid packet received.\n");
		return 1;
	}

	/* only alt tc supported in version 1 */

	/* magic 0x23004200 (4 byte) + value (1 byte) */
	if (msgb_length(msg) != (4 + 1))
		return 1; /* drop packet */

	if (osmo_load32be(msgb_data(msg)) != 0x23004200)
		return 1; /* drop packet */

	/* pull data pointer to next object */
	msgb_pull(msg, 4);

	if (msgb_pull_u8(msg)) {
		LOGP(DL2TP, LOGL_INFO, "ALTCRQ -> SuperChannel requested\n");
		l2tp_tx_altc_rq_superchannel(l2s->connection);
	} else {
		LOGP(DL2TP, LOGL_INFO, "ALTCRQ -> TimeSlot requested\n");
		l2tp_tx_altc_rq_timeslot(l2s->connection);
	}

	return 1;
}


/*!
 * \brief unix_read_cb called when data arrived on the unix socket
 * \param fd
 * \return 0 on success
 */
int unix_read_cb(struct osmo_fd *fd)
{
	struct msgb *msg = l2tp_msgb_alloc();
	int rc;

	struct osmo_wqueue *wqueue = container_of(fd, struct osmo_wqueue, bfd);
	struct l2tp_socket_state *state = container_of(wqueue, struct l2tp_socket_state, wqueue);
	struct traffic_channel *channel = container_of(state, struct traffic_channel, state);

	rc = read(fd->fd, msg->data, msg->data_len);
	if (rc < 0) {
		LOGP(DL2TP, LOGL_ERROR, "%s: read failed %s\n", channel->name, strerror(errno));
		msgb_free(msg);
		return rc;
	} else if (rc == 0) {
		LOGP(DL2TP, LOGL_ERROR, "%s: closing socket because read 0 bytes\n", channel->name);
		msgb_free(msg);
		l2tp_sock_cleanup(fd);
		return 0;
	}

	msgb_put(msg, rc);

	if (!channel->session) {
		LOGP(DL2TP, LOGL_DEBUG, "%s: Drop incoming packet session is full\n", channel->name);
		msgb_free(msg);
		return 1;
	}
	msg->dst = channel->session;

	/* only the rsl_oml has an additional header */
	if (channel->version_control_header) {
		if (lapd_process_version_header(l2i, msg)) {
			/* msg got processed and is finished. */
			msgb_free(msg);
			return 0;
		}
	}

	rc = lapd_lapd_to_ehdlc(l2i, msg);
	if (rc) {
		LOGP(DL2TP, LOGL_NOTICE, "%s: lapd_to_ehlc returned != 0: %d.\n", channel->name, rc);
	}

	msgb_free(msg);
	return 0;
}
