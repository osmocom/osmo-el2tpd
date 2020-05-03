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

#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>


#include "l2tpd_logging.h"

/* default categories */
static struct log_info_cat l2tpd_categories[] = {
	[DL2TP] = {
		.name = "DL2TP",
		.description = "L2TP logging messages",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static const struct log_info l2tpd_log_info = {
	.cat = l2tpd_categories,
	.num_cat = ARRAY_SIZE(l2tpd_categories),
};

void l2tpd_log_init()
{
	osmo_init_logging(&l2tpd_log_info);
}
