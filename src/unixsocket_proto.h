#ifndef UNIXSOCKET_PROTO_H
#define UNIXSOCKET_PROTO_H
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

#define UNIXSOCKET_PROTO_VERSION 0x1

enum {
	UNIXSOCKET_PROTO_DATA = 0x0,
	UNIXSOCKET_PROTO_CONTROL = 0x1,
};

#endif /* UNIXSOCKET_PROTO_H */
