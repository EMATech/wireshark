/* packet-hiqnet.c
 * Harman HiQnet protocol dissector for Wireshark
 * By Raphael Doursenaud <rdoursenaud@free.fr>
 * Copyright 2014 Raphael Doursenaud
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "config.h"

#include <epan/packet.h>

/*
 * See
 *      http://adn.harmanpro.com/site_elements/resources/487_1411413911/HiQnet_third-party_programmers_quick-start_guide_original.pdf
 *      http://hiqnet.harmanpro.com/content/misc/hiqnet%20third%20party%20programmers%20guide%20v2.pdf
 */

#define HIQNET_PORT 3804

#define HIQNET_FLAGS_MASK   0x016f

#define HIQNET_REQACK_FLAG      0x0001
#define HIQNET_ACK_FLAG         0x0002
#define HIQNET_INFO_FLAG        0x0004
#define HIQNET_ERROR_FLAG       0x0008
#define HIQNET_GUARANTEED_FLAG  0x0020
#define HIQNET_MULTIPART_FLAG   0x0040
#define HIQNET_SESSION_FLAG     0x0100

#define HIQNET_DISCOINFO_MSG        0x0000
#define HIQNET_RESERVED0_MSG        0x0001
#define HIQNET_GETNETINFO_MSG       0x0002
#define HIQNET_RESERVED1_MSG        0x0003
#define HIQNET_REQADDR_MSG          0x0004
#define HIQNET_ADDRUSED_MSG         0x0005
#define HIQNET_SETADDR_MSG          0x0006
#define HIQNET_GOODBYE_MSG          0x0007
#define HIQNET_HELLO_MSG            0x0008
#define HIQNET_MULTPARMSET_MSG      0x0100
#define HIQNET_MULTOBJPARMSET_MSG   0x0101
#define HIQNET_PARMSETPCT_MSG       0x0102
#define HIQNET_MULTPARMGET_MSG      0x0103
#define HIQNET_GETATTR_MSG          0x010d
#define HIQNET_MULTPARMSUB_MSG      0x010f
#define HIQNET_PARMSUBPCT_MSG       0x0111
#define HIQNET_MULTPARMUNSUB_MSG    0x0112
#define HIQNET_FEEDBACK_MSG         0x0113
#define HIQNET_PARMSUBALL_MSG       0x0113
#define HIQNET_SUBEVTLOGMSGS_MSG    0x0115
#define HIQNET_GETVDLIST_MSG        0x011a
#define HIQNET_STORE_MSG            0x0124
#define HIQNET_RECALL_MSG           0x0125
#define HIQNET_LOCATE_MSG           0x0129
#define HIQNET_UNSUBEVTLOGMSGS_MSG  0x012b
#define HIQNET_REQEVTLOG_MSG        0x012c

static const value_string messageidnames[] = {
    { HIQNET_DISCOINFO_MSG, "DiscoInfo" },
    { HIQNET_RESERVED0_MSG, "Reserved" },
    { HIQNET_GETNETINFO_MSG, "GetNetworkInfo" },
    { HIQNET_RESERVED1_MSG, "Reserved" },
    { HIQNET_REQADDR_MSG, "RequestAddress" },
    { HIQNET_ADDRUSED_MSG, "AddressUsed" },
    { HIQNET_SETADDR_MSG, "SetAddress" },
    { HIQNET_GOODBYE_MSG, "Goodbye" },
    { HIQNET_HELLO_MSG, "Hello" },
    { HIQNET_MULTPARMSET_MSG, "MultiParamSet" },
    { HIQNET_MULTOBJPARMSET_MSG, "MultiObjectParamSet" },
    { HIQNET_PARMSETPCT_MSG, "ParamSetPercent" },
    { HIQNET_MULTPARMGET_MSG, "MultiParamGet" },
    { HIQNET_GETATTR_MSG, "GetAttributes" },
    { HIQNET_MULTPARMSUB_MSG, "MultiParamSubscribe" },
    { HIQNET_PARMSUBPCT_MSG, "ParamSubscribePercent" },
    { HIQNET_MULTPARMUNSUB_MSG, "MultiParamUnsubscribe" },
    { HIQNET_FEEDBACK_MSG, "Feedback" },
    { HIQNET_PARMSUBALL_MSG, "ParameterSubscribeAll" },
    { HIQNET_SUBEVTLOGMSGS_MSG, "Subscribe Event Log Messages" },
    { HIQNET_GETVDLIST_MSG, "GetVDList" },
    { HIQNET_STORE_MSG, "Store" },
    { HIQNET_RECALL_MSG, "Recall" },
    { HIQNET_LOCATE_MSG, "Locate" },
    { HIQNET_UNSUBEVTLOGMSGS_MSG, "Unsubscribe Event Log Messages" },
    { HIQNET_REQEVTLOG_MSG, "Request Event Log" },
    { 0, NULL }
};

static const value_string flagnames[] = {
    {HIQNET_REQACK_FLAG, "Request Acknowledgement" },
    {HIQNET_ACK_FLAG, "Acknowlegement" },
    {HIQNET_INFO_FLAG, "Information" },
    {HIQNET_ERROR_FLAG, "Error" },
    {HIQNET_GUARANTEED_FLAG, "Guaranteed" },
    {HIQNET_MULTIPART_FLAG, "Multi-part" },
    {HIQNET_SESSION_FLAG, "Session Number" },
    { 0, NULL }
};

static int proto_hiqnet = -1;

static int hf_hiqnet_version = -1;

static gint ett_hiqnet = -1;
static gint ett_hiqnet_flags = -1;

static int hf_hiqnet_headerlen = -1;
static int hf_hiqnet_messagelen = -1;
static int hf_hiqnet_sourcedev = -1;
static int hf_hiqnet_sourceaddr = -1; /* TODO: decode and combine with dev */
static int hf_hiqnet_destdev = -1;
static int hf_hiqnet_destaddr = -1; /* TODO: decode and combine with dev */
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
static int hf_hiqnet_errcode = -1;
static int hf_hiqnet_errstr = -1;
static int hf_hiqnet_startseqno = -1;
static int hf_hiqnet_rembytes = -1;
static int hf_hiqnet_sessnum = -1;
static int hf_hiqnet_node = -1;
static int hf_hiqnet_cost = -1;
static int hf_hiqnet_sernumlen = -1;
static int hf_hiqnet_sernum = -1;
static int hf_hiqnet_maxmsgsize = -1;
static int hf_hiqnet_keepaliveperiod = -1;
static int hf_hiqnet_netid = -1;
static int hf_hiqnet_macaddr = -1;
static int hf_hiqnet_dhcp = -1;
static int hf_hiqnet_ipaddr = -1;
static int hf_hiqnet_subnetmsk = -1;
static int hf_hiqnet_gateway = -1;
static int hf_hiqnet_flagmask = -1;


static void
dissect_hiqnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 headerlen = tvb_get_guint8(tvb, 1);
    guint32 messagelen = tvb_get_ntohl(tvb, 2);
    guint16 srcdev = tvb_get_ntohs(tvb, 6);
    guint32 srcaddr = tvb_get_ntohl(tvb, 8);
    guint16 dstdev = tvb_get_ntohs(tvb, 12);
    guint32 dstaddr = tvb_get_ntohl(tvb, 14);
    guint16 messageid = tvb_get_ntohs(tvb, 18);
    guint16 flags = tvb_get_ntohs(tvb, 20);

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
        proto_tree *hiqnet_session_tree = NULL;
        proto_tree *hiqnet_error_tree = NULL;
        proto_tree *hiqnet_multipart_tree = NULL;
        proto_tree *hiqnet_payload_tree = NULL;
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

        /* Standard header */
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_headerlen, tvb, offset, 1, ENC_BIG_ENDIAN);
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
        /* Message for enabled flags */
        if (flags & HIQNET_REQACK_FLAG) {
            proto_item_append_text(hiqnet_flags, " %s",
                try_val_to_str(HIQNET_REQACK_FLAG, flagnames));
        }
        if (flags & HIQNET_ACK_FLAG) {
            proto_item_append_text(hiqnet_flags, " %s",
                try_val_to_str(HIQNET_ACK_FLAG, flagnames));
        }
        if (flags & HIQNET_INFO_FLAG) {
            proto_item_append_text(hiqnet_flags, " %s",
                try_val_to_str(HIQNET_INFO_FLAG, flagnames));
        }
        if (flags & HIQNET_ERROR_FLAG) {
            proto_item_append_text(hiqnet_flags, " %s",
                try_val_to_str(HIQNET_ERROR_FLAG, flagnames));
        }
        if (flags & HIQNET_GUARANTEED_FLAG) {
            proto_item_append_text(hiqnet_flags, " %s",
                try_val_to_str(HIQNET_GUARANTEED_FLAG, flagnames));
        }
        if (flags & HIQNET_MULTIPART_FLAG) {
            proto_item_append_text(hiqnet_flags, " %s",
                try_val_to_str(HIQNET_MULTIPART_FLAG, flagnames));
        }
        if (flags & HIQNET_SESSION_FLAG) {
            proto_item_append_text(hiqnet_flags, " %s",
                val_to_str(HIQNET_SESSION_FLAG, flagnames, "Unknown"));
        }
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

        /* Optional headers */
        if (flags & HIQNET_MULTIPART_FLAG) {
            /* TODO: rebuild the full message */
            hiqnet_multipart_tree = proto_tree_add_subtree(hiqnet_tree, tvb, offset, 2, ett_hiqnet, NULL, "Multi-part");
            proto_tree_add_item(hiqnet_multipart_tree, hf_hiqnet_startseqno, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(hiqnet_multipart_tree, hf_hiqnet_rembytes, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
        if (flags & HIQNET_SESSION_FLAG) {
            hiqnet_session_tree = proto_tree_add_subtree(hiqnet_tree, tvb, offset, 2, ett_hiqnet, NULL, "Session");
            proto_tree_add_item(hiqnet_session_tree, hf_hiqnet_sessnum, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
        /* According to the spec, error header should always be the last */
        if (flags & HIQNET_ERROR_FLAG) {
            /* TODO: mark the erroneous frame */
            hiqnet_error_tree = proto_tree_add_subtree(hiqnet_tree, tvb, offset, 2, ett_hiqnet, NULL, "Error");
            proto_tree_add_item(hiqnet_error_tree, hf_hiqnet_errcode, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(hiqnet_error_tree, hf_hiqnet_errstr, tvb, offset, headerlen - offset, ENC_BIG_ENDIAN);
        }

        /* Payload(s) */
        offset = headerlen; /* Make sure we are at the payload start */
        hiqnet_payload_tree = proto_tree_add_subtree(
            hiqnet_tree, tvb, offset, messagelen - headerlen, ett_hiqnet, NULL, "Payload");
        /* TODO: decode payloads */
        if (messageid == HIQNET_DISCOINFO_MSG) {
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_node, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_cost, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_sernumlen, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_sernum, tvb, offset, 16, ENC_BIG_ENDIAN);
            offset += 16;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_maxmsgsize, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_keepaliveperiod, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_netid, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_macaddr, tvb, offset, 6, ENC_BIG_ENDIAN);
            offset += 6;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_dhcp, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_ipaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_subnetmsk, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_gateway, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
        if (messageid == HIQNET_HELLO_MSG) {
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_sessnum, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_flagmask, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            /* TODO: decode flag mask */
        }
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
                NULL, HIQNET_FLAGS_MASK,
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
        { &hf_hiqnet_errcode,
            { "Error code", "hiqnet.errcode",
                FT_UINT8, BASE_DEC_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_errstr,
            { "Error string", "hiqnet.errstr",
                FT_STRING, STR_UNICODE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_startseqno,
            { "Start seq. no.", "hiqnet.ssno",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_rembytes,
            { "Remaining bytes", "hiqnet.rembytes",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_sessnum,
            { "Session number", "hiqnet.sessnum",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_node,
            { "Node", "hiqnet.node",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_cost,
            { "Cost", "hiqnet.cost",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_sernumlen,
            { "Serial number length", "hiqnet.sernumlen",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_sernum,
            { "Serial number", "hiqnet.sernum",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_maxmsgsize,
            { "Max message size", "hiqnet.maxmsgsize",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_keepaliveperiod,
            { "Keepalive period (ms)", "hiqnet.keepaliveperiod",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_netid,
            { "Network ID", "hiqnet.netid",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_macaddr,
            { "MAC address", "hiqnet.macaddr",
                FT_ETHER, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_dhcp,
            { "DHCP", "hiqnet.dhcp",
                FT_BOOLEAN, 1,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_ipaddr,
            { "IP Address", "hiqnet.ipaddr",
                FT_IPv4, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_subnetmsk,
            { "Subnet mask", "hiqnet.subnetmsk",
                FT_IPv4, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_gateway,
            { "Gateway", "hiqnet.gateway",
                FT_IPv4, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_flagmask,
            { "Flag mask", "hiqnet.flagmask",
                FT_UINT16, BASE_HEX,
                NULL, HIQNET_FLAGS_MASK,
                NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_hiqnet,
        &ett_hiqnet_flags
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
    dissector_add_uint("tcp.port", HIQNET_PORT, hiqnet_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 expandtab:
 * :indentSize=4:noTabs=true:
 */
