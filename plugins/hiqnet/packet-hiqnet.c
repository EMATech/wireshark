/*
 * Harman HiQnet protocol dissector for Wireshark
 * Copyright (C) 2014 Raphaël Doursenaud <rdoursenaud@free.fr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "config.h"

#include <epan/packet.h>

#define HIQNET_PORT 3804

static int proto_hiqnet = -1;


static void
dissect_hiqnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HiQnet");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);
}


void
proto_register_hiqnet(void)
{
    proto_hiqnet = proto_register_protocol (
        "Harman HiQnet", /* name       */
        "HiQnet",      /* short name */
        "hiqnet"       /* abbrev     */
        );
}


void
proto_reg_handoff_hiqnet(void)
{
    static dissector_handle_t hiqnet_handle;

    hiqnet_handle = create_dissector_handle(dissect_hiqnet, proto_hiqnet);
    dissector_add_uint("udp.port", HIQNET_PORT, hiqnet_handle);
}
