
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

/* accept a new connection */
static int mncc_sock_accept(struct osmo_fd *bfd, unsigned int flags)
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
		osmo_fd_unregister(conn_bfd);
		close(conn_bfd->fd);
		return 0;
	}

	conn_bfd->fd = rc;
	conn_bfd->when = BSC_FD_READ | BSC_FD_WRITE;

	if (osmo_fd_register(conn_bfd) != 0) {
		LOGP(state->log_class, LOGL_ERROR, "Failed to register new connection fd\n");
		close(conn_bfd->fd);
		conn_bfd->fd = -1;
		return -1;
	}

	LOGP(state->log_class, LOGL_NOTICE, "MNCC Socket has connection with external "
		"call control application\n");

	return 0;
}

void l2tp_set_read_callback(struct l2tp_socket_state *state, int (*read_cb)(struct osmo_fd *fd))
{
	state->wqueue.read_cb = read_cb;
}

void l2tp_set_write_callback(struct l2tp_socket_state *state, int (*write_cb)(struct osmo_fd *fd, struct msgb *msg))
{
	state->wqueue.write_cb = write_cb;
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
int l2tp_socket_init(struct l2tp_socket_state *state, const char *sock_path, int queue_len)
{
	struct osmo_fd *bfd;
	int rc;

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
	bfd->cb = mncc_sock_accept;

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
