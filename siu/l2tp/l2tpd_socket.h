#pragma once

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

int l2tp_socket_init(struct l2tp_socket_state *state, const char *sock_path, int queue_len);
int l2tp_socket_enqueue(struct l2tp_socket_state *state, struct msgb *msg);

void l2tp_set_read_callback(struct l2tp_socket_state *state, int (*read_cb)(struct osmo_fd *fd));
void l2tp_set_write_callback(struct l2tp_socket_state *state, int (*write_cb)(struct osmo_fd *fd, struct msgb *msg));
