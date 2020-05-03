#pragma once

/* (C) 2016 by sysmocom - s.f.m.c. GmbH, Author: Alexander Couzens <lynxis@fe80.eu>
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

#include <osmocom/core/write_queue.h>

/*!
 * \brief The socket_state struct represents a unix socket
 */
struct l2tp_socket_state {
	/*! write queue of our data socket */
	struct osmo_wqueue wqueue;
	/*! \brief listen_bfd listening socket*/
	struct osmo_fd listen_bfd;

	int log_class;
};

int l2tp_socket_init(struct l2tp_socket_state *state, const char *sock_path, int queue_len, int log_class);
int l2tp_socket_enqueue(struct l2tp_socket_state *state, struct msgb *msg);

void l2tp_set_read_callback(struct l2tp_socket_state *state, int (*read_cb)(struct osmo_fd *fd));
int l2tp_sock_cleanup(struct osmo_fd *bfd);
