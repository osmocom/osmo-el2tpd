#pragma once

struct msgb;

int l2tp_rcvmsg(struct msgb *msg);

struct msgb *l2tp_msgb_alloc(void);
