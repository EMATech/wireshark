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

#define HIQNET_REQACK_FLAG      0x0001
#define HIQNET_ACK_FLAG         0x0002
#define HIQNET_INFO_FLAG        0x0004
#define HIQNET_ERROR_FLAG       0x0008
#define HIQNET_GUARANTEED_FLAG  0x0010
#define HIQNET_MULTIPART_FLAG   0x0040
#define HIQNET_SESSION_FLAG     0x0100

static const value_string messageidnames[] = {
        { 0x0000, "DiscoInfo" },
        { 0x0002, "GetNetworkInfo" },
        { 0x0004, "RequestAddress / AddressUsed" },
        { 0x0006, "SetAddress" },
        { 0x0007, "Goodbye" },
        { 0x0008, "Hello" },
        { 0x010d, "GetAttributes" },
        { 0x011a, "GetVDList" },
        { 0x0124, "Store" },
        { 0x0125, "Recall" },
        { 0x0129, "Locate" },
        { 0x0115, "Subscribe Event Log Messages" },
        { 0x012b, "Unsubscribe Event Log Messages" },
        { 0x012c, "Request Event Log" },
        { 0x0100, "MultiParamSet" },
        { 0x0103, "MultiParamGet" },
        { 0x010f, "MultiParamSubscribe" },
        { 0x0112, "MultiParamUnsubscribe" },
        { 0x0101, "MultiObjectParamSet" },
        { 0x0102, "ParamSetPercent" },
        { 0x0111, "ParamSubscribePercent" },
};

static int proto_hiqnet = -1;

static int hf_hiqnet_version = -1;

static gint ett_hiqnet = -1;
static gint ett_hiqnet_flags = -1;

static int hf_hiqnet_headerlen = -1;
static int hf_hiqnet_messagelen = -1;
static int hf_hiqnet_sourcedev = -1;
static int hf_hiqnet_sourceaddr = -1; // TODO: decode and combine with dev
static int hf_hiqnet_destdev = -1;
static int hf_hiqnet_destaddr = -1; // TODO: decode and combine with dev
static int hf_hiqnet_messageid = -1;
static int hf_hiqnet_flags = -1;
static int hf_hiqnet_reqack_flag = -1;
static int hf_hiqnet_ack_flag = -1;
static int hf_hiqnet_info_flag = -1;
static int hf_hiqnet_error_flag = -1;
static int hf_hiqnet_guaranteed_flag = -1;
static int hf_hiqnet_multipart_flag = -1;
static int hf_hiqnet_session_flag = -1;
static int hf_hiqnet_hopcnt = -1;
static int hf_hiqnet_seqnum = -1;


static void
dissect_hiqnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 headerlen = tvb_get_guint8(tvb, 1);
    guint32 messagelen = tvb_get_ntohl(tvb, 2);
    guint16 srcdev = tvb_get_ntohs(tvb, 7);
    guint32 srcaddr = tvb_get_ntohl(tvb, 9);
    guint16 dstdev = tvb_get_ntohs(tvb, 13);
    guint32 dstaddr = tvb_get_ntohl(tvb, 15);
    guint16 messageid = tvb_get_ntohs(tvb, 19);
    guint16 flags = tvb_get_ntohs(tvb, 21);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HiQnet");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Msg: %s, Src: %u.%u, Dst: %u.%u",
        val_to_str(messageid, messageidnames, "Unknown (0x%04x)"), srcdev, srcaddr, dstdev, dstaddr);

    if (tree) { /* we are being asked for details */
        proto_item *ti = NULL;
        proto_tree *hiqnet_tree = NULL;
        proto_tree *hiqnet_header_tree = NULL;
        proto_item *hiqnet_flags = NULL;
        proto_tree *hiqnet_flags_tree = NULL;
        gint offset = 0;

        ti = proto_tree_add_item(tree, proto_hiqnet, tvb, 0, messagelen, ENC_NA);
        proto_item_append_text(ti, ", Msg: %s",
                val_to_str(messageid, messageidnames, "Unknown (0x%04x)"));
        proto_item_append_text(ti, ", Src %u.%u",
            srcdev, srcaddr);
        proto_item_append_text(ti, ", Dst: %u.%u",
            dstdev, dstaddr);
        hiqnet_tree = proto_item_add_subtree(ti, ett_hiqnet);

        /* Header subtree */
        hiqnet_header_tree = proto_tree_add_subtree(hiqnet_tree, tvb, 0, headerlen, ett_hiqnet, NULL, "Header");

        // Standard header
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_headerlen, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_messagelen, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_sourcedev, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_sourceaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_destdev, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_destaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_messageid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        hiqnet_flags = proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
        // TODO: add message for enabled flags
        if (flags) {
            hiqnet_flags_tree = proto_item_add_subtree(hiqnet_flags, ett_hiqnet_flags);
            proto_tree_add_item(hiqnet_flags_tree, hf_hiqnet_reqack_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(hiqnet_flags_tree, hf_hiqnet_ack_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(hiqnet_flags_tree, hf_hiqnet_info_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(hiqnet_flags_tree, hf_hiqnet_error_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(hiqnet_flags_tree, hf_hiqnet_guaranteed_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(hiqnet_flags_tree, hf_hiqnet_multipart_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(hiqnet_flags_tree, hf_hiqnet_session_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
        }
        offset += 2;
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_hopcnt, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_seqnum, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        // TODO: Optional headers

        // Payload(s)
        proto_tree_add_subtree(hiqnet_tree, tvb, headerlen, messagelen - headerlen, ett_hiqnet, NULL, "Payload");
        // TODO: decode payloads
    }
}


void
proto_register_hiqnet(void)
{
    static hf_register_info hf[] = {
        { &hf_hiqnet_version,
            { "Version", "hiqnet.version",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_headerlen,
            { "Header length", "hiqnet.hlen",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_messagelen,
            { "Message length", "hiqnet.mlen",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_sourcedev,
            { "Source device", "hiqnet.srcdev",
                FT_UINT8, BASE_DEC_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_sourceaddr,
            { "Source address", "hiqnet.srcaddr",
                FT_UINT16, BASE_DEC_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_destdev,
            { "Destination device", "hiqnet.dstdev",
                FT_UINT8, BASE_DEC_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_destaddr,
            { "Destination address", "hiqnet.dstaddr",
                FT_UINT16, BASE_DEC_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_messageid,
            { "Message ID", "hiqnet.msgid",
                FT_UINT16, BASE_HEX,
                VALS(messageidnames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_flags,
            { "Flags", "hiqnet.flags",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_reqack_flag,
            { "Request acknowledgement flag", "foo.flags.reqack",
                FT_BOOLEAN, 16,
                NULL, HIQNET_REQACK_FLAG,
                NULL, HFILL }
        },
        { &hf_hiqnet_ack_flag,
            { "Acknowledgement flag", "foo.flags.ack",
                FT_BOOLEAN, 16,
                NULL, HIQNET_ACK_FLAG,
                NULL, HFILL }
        },
        { &hf_hiqnet_info_flag,
            { "Information flag", "foo.flags.info",
                FT_BOOLEAN, 16,
                NULL, HIQNET_INFO_FLAG,
                NULL, HFILL }
        },
        { &hf_hiqnet_error_flag,
            { "Error flag", "foo.flags.error",
                FT_BOOLEAN, 16,
                NULL, HIQNET_ERROR_FLAG,
                NULL, HFILL }
        },
        { &hf_hiqnet_guaranteed_flag,
            { "Guaranteed flag", "foo.flags.guar",
                FT_BOOLEAN, 16,
                NULL, HIQNET_GUARANTEED_FLAG,
                NULL, HFILL }
        },
        { &hf_hiqnet_multipart_flag,
            { "Multipart flag", "foo.flags.multi",
                FT_BOOLEAN, 16,
                NULL, HIQNET_MULTIPART_FLAG,
                NULL, HFILL }
        },
        { &hf_hiqnet_session_flag,
            { "Session flag", "foo.flags.session",
                FT_BOOLEAN, 16,
                NULL, HIQNET_SESSION_FLAG,
                NULL, HFILL }
        },
        { &hf_hiqnet_hopcnt,
            { "Hop count", "hiqnet.hc",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_seqnum,
            { "Sequence number", "hiqnet.seqnum",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_hiqnet,
        &ett_hiqnet_flags,
    };

    proto_hiqnet = proto_register_protocol (
        "Harman HiQnet", /* name       */
        "HiQnet",        /* short name */
        "hiqnet"         /* abbrev     */
    );

    proto_register_field_array(proto_hiqnet, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_hiqnet(void)
{
    static dissector_handle_t hiqnet_handle;

    hiqnet_handle = create_dissector_handle(dissect_hiqnet, proto_hiqnet);
    dissector_add_uint("udp.port", HIQNET_PORT, hiqnet_handle);
}
