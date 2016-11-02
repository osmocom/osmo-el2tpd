/* generic unix socket interface
 *
 * (C) 2016 by Alexander Couzens <lynxis@fe80.eu>
 *
 * All Rights Reserved
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

#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>


#include <osmocom/core/write_queue.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/loggingrb.h>
#include <osmocom/core/socket.h>

#include "l2tpd_socket.h"


static int l2tp_sock_write(struct osmo_fd *bfd, struct msgb *msg)
{
	int rc;

	rc = write(bfd->fd, msg->data, msg->len);
	if (rc != msg->len)
		LOGP(DLCTRL, LOGL_ERROR, "Failed to write message to the unix connection.\n");

	return rc;
}

int l2tp_sock_cleanup(struct osmo_fd *bfd)
{
	int rc;
	struct osmo_wqueue *wq = container_of(bfd, struct osmo_wqueue, bfd);

	osmo_wqueue_clear(wq);
	rc = close(bfd->fd);
	osmo_fd_unregister(bfd);
	bfd->fd = -1;

	return rc;
}

/* accept a new connection */
static int l2tp_sock_accept(struct osmo_fd *bfd, unsigned int flags)
{
	struct l2tp_socket_state *state = container_of(bfd, struct l2tp_socket_state, listen_bfd);
	struct osmo_fd *conn_bfd = &state->wqueue.bfd;
	struct sockaddr_un un_addr;
	socklen_t len;
	int rc;

	len = sizeof(un_addr);
	rc = accept(bfd->fd, (struct sockaddr *) &un_addr, &len);
	if (rc < 0) {
		LOGP(state->log_class, LOGL_ERROR, "Failed to accept a new connection\n");
		return -1;
	}

	if (conn_bfd->fd >= 0) {
		LOGP(state->log_class, LOGL_NOTICE, "There is already one connection to the socket\n");
		l2tp_sock_cleanup(conn_bfd);
		return 0;
	}

	conn_bfd->fd = rc;
	conn_bfd->when = BSC_FD_READ;

	if (osmo_fd_register(conn_bfd) != 0) {
		LOGP(state->log_class, LOGL_ERROR, "Failed to register new connection fd\n");
		close(conn_bfd->fd);
		conn_bfd->fd = -1;
		return -1;
	}

	state->wqueue.write_cb = l2tp_sock_write;
	state->wqueue.except_cb = l2tp_sock_cleanup;

	LOGP(state->log_class, LOGL_NOTICE, "Unix Socket has connection with external "
		"call control application\n");

	return 0;
}

void l2tp_set_read_callback(struct l2tp_socket_state *state, int (*read_cb)(struct osmo_fd *fd))
{
	state->wqueue.read_cb = read_cb;
}

/*!
 * \brief l2tp_enqueue_data
 * \param sock
 * \return 0 on success
 */
int l2tp_socket_enqueue(struct l2tp_socket_state *state, struct msgb *msg)
{
	return osmo_wqueue_enqueue(&state->wqueue, msg);
}

/*!
 * \brief l2tp_socket_init
 * \param sock
 * \param sock_path
 * \return 0 on success
 */
int l2tp_socket_init(struct l2tp_socket_state *state, const char *sock_path, int queue_len, int log_class)
{
	struct osmo_fd *bfd;
	int rc;

	state->log_class = log_class;
	osmo_wqueue_init(&state->wqueue, queue_len);
	state->wqueue.bfd.fd = -1;

	bfd = &state->listen_bfd;
	bfd->fd = osmo_sock_unix_init(SOCK_SEQPACKET, 0, sock_path,
		OSMO_SOCK_F_BIND);
	if (bfd->fd < 0) {
		LOGP(state->log_class, LOGL_ERROR, "Could not create unix socket: %s: %s\n",
		     sock_path, strerror(errno));
		talloc_free(state);
		return -1;
	}

	bfd->when = BSC_FD_READ;
	bfd->cb = l2tp_sock_accept;

	rc = osmo_fd_register(bfd);
	if (rc < 0) {
		LOGP(state->log_class, LOGL_ERROR, "Could not register listen fd: %d\n", rc);
		close(bfd->fd);
		talloc_free(state);
		return rc;
	}

	LOGP(state->log_class, LOGL_NOTICE, "MNCC socket at %s\n", sock_path);
	return 0;
}
