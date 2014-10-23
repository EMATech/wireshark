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

#define HIQNET_CATEGORIES_MASK  0x00004fff

#define HIQNET_APPLICATION_CAT  0x00000001
#define HIQNET_CONF_CAT         0x00000002
#define HIQNET_AUDIONET_CAT     0x00000003
#define HIQNET_CTRLNET_CAT      0x00000004
#define HIQNET_VENDNET_CAT      0x00000005
#define HIQNET_STARTUP_CAT      0x00000006
#define HIQNET_DSP_CAT          0x00000007
#define HIQNET_MISC_CAT         0x00000008
#define HIQNET_CTRLLOG_CAT      0x00000009
#define HIQNET_FOREIGNPROTO_CAT 0x0000000a
#define HIQNET_DIGIO_CAT        0x0000000b
#define HIQNET_CTRLSURF_CAT     0x0000000e

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
#define HIQNET_SETATTR_MSG          0x010e /* Reverse engineered. Not part of the official spec. */
#define HIQNET_MULTPARMSUB_MSG      0x010f
#define HIQNET_PARMSUBPCT_MSG       0x0111
#define HIQNET_MULTPARMUNSUB_MSG    0x0112
#define HIQNET_PARMSUBALL_MSG       0x0113
#define HIQNET_PARMUNSUBALL_MSG     0x0114
#define HIQNET_SUBEVTLOGMSGS_MSG    0x0115
#define HIQNET_GETVDLIST_MSG        0x011a
#define HIQNET_STORE_MSG            0x0124
#define HIQNET_RECALL_MSG           0x0125
#define HIQNET_LOCATE_MSG           0x0129
#define HIQNET_UNSUBEVTLOGMSGS_MSG  0x012b
#define HIQNET_REQEVTLOG_MSG        0x012c

#define HIQNET_TCPIP_NET    1
#define HIQNET_RS232_NET    4

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
    { HIQNET_SETATTR_MSG, "SetAttribute" }, /* Reverse engineered. Not part of the official spec. */
    { HIQNET_MULTPARMUNSUB_MSG, "MultiParamUnsubscribe" },
    { HIQNET_PARMSUBALL_MSG, "ParameterSubscribeAll" },
    { HIQNET_PARMUNSUBALL_MSG, "ParameterUnSubscribeAll" },
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
    { HIQNET_REQACK_FLAG, "Request Acknowledgement" },
    { HIQNET_ACK_FLAG, "Acknowlegement" },
    { HIQNET_INFO_FLAG, "Information" },
    { HIQNET_ERROR_FLAG, "Error" },
    { HIQNET_GUARANTEED_FLAG, "Guaranteed" },
    { HIQNET_MULTIPART_FLAG, "Multi-part" },
    { HIQNET_SESSION_FLAG, "Session Number" },
    { 0, NULL }
};

static const value_string datatypenames[] = {
    { 0, "BYTE" },
    { 1, "UBYTE" },
    { 2, "WORD" },
    { 3, "UWORD" },
    { 4, "LONG" },
    { 5, "ULONG" },
    { 6, "FLOAT32" },
    { 7, "FLOAT64" },
    { 8, "BLOCK" },
    { 9, "STRING" },
    { 10, "LONG64" },
    { 11, "ULONG64" },
    { 0, NULL }
};

static const value_string actionnames[] = {
    { 0, "Parameters" },
    { 1, "Subscriptions" },
    { 2, "Scenes" },
    { 3, "Snapshots" },
    { 4, "Presets" },
    { 5, "Venue" },
    { 0, NULL }
};

static const value_string timenames[] = {
    { 0x0000, "Turn off locate LEDs" },
    { 0xffff, "Turn on locate LEDs" },
    { 0, NULL }
};

static const value_string eventcategorynames[] = {
    { 0, "Unassigned" },
    { 1, "Application" },
    { 2, "Configuration" },
    { 3, "Audio Network" },
    { 4, "Control Network" },
    { 5, "Vendor Network" },
    { 6, "Startup" },
    { 7, "DSP" },
    { 8, "Miscellaneous" },
    { 9, "Control Logic" },
    { 10, "Foreign Protocol" },
    { 11, "Digital I/O" },
    { 12, "Unassigned" },
    { 13, "Unassigned" },
    { 14, "Control Surface" },
    { 15, "Unassigned" },
    { 16, "Unassigned" },
    { 17, "Unassigned" },
    { 18, "Unassigned" },
    { 19, "Unassigned" },
    { 20, "Unassigned" },
    { 21, "Unassigned" },
    { 22, "Unassigned" },
    { 23, "Unassigned" },
    { 24, "Unassigned" },
    { 25, "Unassigned" },
    { 26, "Unassigned" },
    { 27, "Unassigned" },
    { 28, "Unassigned" },
    { 29, "Unassigned" },
    { 30, "Unassigned" },
    { 31, "Unassigned" },
    { 0, NULL }
};

static const value_string eventidnames[] = {
    { 0x0001, "Invalid Version" },
    { 0x0002, "Invalid Length" },
    { 0x0003, "Invalid Virtual Device" },
    { 0x0004, "Invalid Object" },
    { 0x0005, "Invalid Parameter" },
    { 0x0006, "Invalid Message ID" },
    { 0x0007, "Invalid Value" },
    { 0x0008, "Resource Unavailable" },
    { 0x0009, "Unsupported" },
    { 0x000a, "Invalid Virtual Device Class" },
    { 0x000b, "Invalid Object Class" },
    { 0x000c, "Invalid Parameter Class" },
    { 0x000d, "Invalid Attribute ID" },
    { 0x000e, "Invalid DataType" },
    { 0x000f, "Invalid Configuration" },
    { 0x0010, "Flash Error" },
    { 0x0011, "Not a Router" },
    { 0, NULL }
};

static const value_string prioritynames[] = {
    { 0, "Fault" },
    { 1, "Warning" },
    { 2, "Information" },
    { 0, NULL }
};

static const value_string networknames[] = {
    { HIQNET_TCPIP_NET, "TCP/IP" },
    { 2, "Reserved" },
    { 3, "Reserved" },
    { HIQNET_RS232_NET, "RS232" },
    { 0, NULL }
};

static const value_string paritynames[] = {
    { 0, "None" },
    { 1, "Odd" },
    { 2, "Even" },
    { 3, "Mark" },
    { 4, "Space" },
    { 0, NULL }
};

static const value_string stopbitsnames[] = {
    { 0, "1 Bits" },
    { 1, "1.5 Bits" },
    { 2, "2 Bits" },
    { 0, NULL }
};

static const value_string flowcontrolnames[] = {
    { 0, "None" },
    { 1, "Hardware" },
    { 2, "XON/OFF" },
    { 0, NULL }
};

static const gint hiqnet_datasize_per_type[] = { 1, 1, 2, 2, 4, 4, 4, 8, -1, -1, 8, 8 };

static int proto_hiqnet = -1;

static int hf_hiqnet_version = -1;

static gint ett_hiqnet = -1;
static gint ett_hiqnet_flags = -1;
static gint ett_hiqnet_cats = -1;

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
static int hf_hiqnet_paramcount = -1;
static int hf_hiqnet_paramid = -1;
static int hf_hiqnet_datatype = -1;
static int hf_hiqnet_value = -1;
static int hf_hiqnet_vdobject = -1;
static int hf_hiqnet_changetype = -1;
static int hf_hiqnet_sensrate = -1;
static int hf_hiqnet_initupd = -1;
static int hf_hiqnet_subcount = -1;
static int hf_hiqnet_pubparmid = -1;
static int hf_hiqnet_subtype = -1;
static int hf_hiqnet_subaddr = -1;
static int hf_hiqnet_subparmid = -1;
static int hf_hiqnet_reserved0 = -1;
static int hf_hiqnet_reserved1 = -1;
static int hf_hiqnet_attrcount = -1;
static int hf_hiqnet_attrid = -1;
static int hf_hiqnet_datalen = -1;
static int hf_hiqnet_string = -1;
static int hf_hiqnet_wrkgrppath = -1;
static int hf_hiqnet_numvds = -1;
static int hf_hiqnet_vdaddr = -1;
static int hf_hiqnet_vdclassid = -1;
static int hf_hiqnet_stract = -1;
static int hf_hiqnet_strnum = -1;
static int hf_hiqnet_scope = -1;
static int hf_hiqnet_recact = -1;
static int hf_hiqnet_recnum = -1;
static int hf_hiqnet_strlen = -1;
static int hf_hiqnet_time = -1;
static int hf_hiqnet_maxdatasize = -1;
static int hf_hiqnet_catfilter = -1;
static int hf_hiqnet_app_cat = -1;
static int hf_hiqnet_conf_cat = -1;
static int hf_hiqnet_audionet_cat = -1;
static int hf_hiqnet_ctrlnet_cat = -1;
static int hf_hiqnet_vendnet_cat = -1;
static int hf_hiqnet_startup_cat = -1;
static int hf_hiqnet_dsp_cat = -1;
static int hf_hiqnet_misc_cat = -1;
static int hf_hiqnet_ctrlog_cat = -1;
static int hf_hiqnet_foreignproto_cat = -1;
static int hf_hiqnet_digio_cat = -1;
static int hf_hiqnet_ctrlsurf_cat = -1;
static int hf_hiqnet_entrieslen = -1;
static int hf_hiqnet_category = -1;
static int hf_hiqnet_eventid = -1;
static int hf_hiqnet_priority = -1;
static int hf_hiqnet_eventseqnum = -1;
static int hf_hiqnet_eventtime = -1;
static int hf_hiqnet_eventdate = -1;
static int hf_hiqnet_eventinfo = -1;
static int hf_hiqnet_eventadddata = -1;
static int hf_hiqnet_objcount = -1;
static int hf_hiqnet_objdest = -1;
static int hf_hiqnet_paramval = -1;
static int hf_hiqnet_ifacecount = -1;
static int hf_hiqnet_comid = -1;
static int hf_hiqnet_baudrate = -1;
static int hf_hiqnet_parity = -1;
static int hf_hiqnet_stopbits = -1;
static int hf_hiqnet_databits = -1;
static int hf_hiqnet_flowcontrol = -1;
static int hf_hiqnet_devaddr = -1;
static int hf_hiqnet_newdevaddr = -1;

static void dissect_hiqnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

gint hiqnet_display_netinfo(proto_tree *hiqnet_payload_tree, tvbuff_t *tvb, gint offset);

gint hiqnet_display_tcpipnetinfo(proto_tree *hiqnet_payload_tree, tvbuff_t *tvb, gint offset);

gint hiqnet_display_rs232netinfo(proto_tree *hiqnet_payload_tree, tvbuff_t *tvb, gint offset);

gint hiqnet_display_sernum(proto_tree *hiqnet_payload_tree, tvbuff_t *tvb, gint offset);

gint hiqnet_display_paramsub(proto_tree *hiqnet_payload_tree, tvbuff_t *tvb, gint offset);

gint hiqnet_display_data(proto_tree *hiqnet_payload_tree, tvbuff_t *tvb, gint offset);

void hiqnet_decode_flags(guint16 flags, proto_item *hiqnet_flags);

void hiqnet_display_flags(guint16 flags, proto_item *hiqnet_flags_item, tvbuff_t *tvb, gint offset);

void hiqnet_decode_cats(guint32 cats, proto_item *hiqnet_cats);

void hiqnet_display_cats(guint32 cats, proto_item *hiqnet_cats_item, tvbuff_t *tvb, gint offset);

void proto_register_hiqnet(void);

void proto_reg_handoff_hiqnet(void);

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
    guint16 flagmask = 0;
    guint16 paramcount = 0;
    guint16 subcount = 0;
    guint16 attrcount = 0;
    gint strlen;
    guint16 vdscount = 0;
    guint32 cats = 0;
    guint16 entriescount = 0;
    guint16 objcount = 0;
    guint16 ifacecount = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HiQnet");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Msg: %s, Src: %u.%u, Dst: %u.%u",
        val_to_str(messageid, messageidnames, "Unknown (0x%04x)"), srcdev, srcaddr, dstdev, dstaddr);

    if (tree) { /* we are being asked for details */
        proto_item *ti = NULL;
        proto_tree *hiqnet_tree = NULL;
        proto_tree *hiqnet_header_tree = NULL;
        proto_item *hiqnet_flags_item = NULL;
        proto_tree *hiqnet_session_tree = NULL;
        proto_tree *hiqnet_error_tree = NULL;
        proto_tree *hiqnet_multipart_tree = NULL;
        proto_tree *hiqnet_payload_tree = NULL;
        proto_item *hiqnet_flagmask_item = NULL;
        proto_item *hiqnet_cats_item = NULL;
        proto_tree *hiqnet_parameters_tree = NULL;
        proto_tree *hiqnet_attributes_tree = NULL;
        proto_tree *hiqnet_vds_tree = NULL;
        proto_tree *hiqnet_events_tree = NULL;
        proto_tree *hiqnet_subscriptions_tree = NULL;
        proto_tree *hiqnet_objects_tree = NULL;
        proto_tree *hiqnet_ifaces_tree = NULL;
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
        hiqnet_flags_item = proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
        hiqnet_decode_flags(flags, hiqnet_flags_item);
        hiqnet_display_flags(flags, hiqnet_flags_item, tvb, offset);
        offset += 2;
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_hopcnt, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_seqnum, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* Optional headers */
        if (flags & HIQNET_ERROR_FLAG) {
            /* TODO: mark the erroneous frame */
            hiqnet_error_tree = proto_tree_add_subtree(hiqnet_tree, tvb, offset, 2, ett_hiqnet, NULL, "Error");
            proto_tree_add_item(hiqnet_error_tree, hf_hiqnet_errcode, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(hiqnet_error_tree, hf_hiqnet_errstr, tvb, offset, headerlen - offset, ENC_UCS_2);
        }
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

        /* Payload(s) */
        offset = headerlen; /* Make sure we are at the payload start */
        hiqnet_payload_tree = proto_tree_add_subtree(
            hiqnet_tree, tvb, offset, messagelen - headerlen, ett_hiqnet, NULL, "Payload");
        if (messageid == HIQNET_DISCOINFO_MSG) {
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_devaddr, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_cost, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            offset = hiqnet_display_sernum(hiqnet_payload_tree, tvb, offset);
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_maxmsgsize, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_keepaliveperiod, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            offset = hiqnet_display_netinfo(hiqnet_payload_tree, tvb, offset);
        }
        if (messageid == HIQNET_HELLO_MSG) {
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_sessnum, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            hiqnet_flagmask_item = proto_tree_add_item(
                hiqnet_payload_tree, hf_hiqnet_flagmask, tvb, offset, 2, ENC_BIG_ENDIAN);
            flagmask = tvb_get_ntohs(tvb, offset);
            hiqnet_decode_flags(flagmask, hiqnet_flagmask_item);
            hiqnet_display_flags(flagmask, hiqnet_flagmask_item, tvb, offset);
            offset += 2;
        }
        if (messageid == HIQNET_MULTPARMGET_MSG) {
            paramcount = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_paramcount, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            hiqnet_parameters_tree = proto_tree_add_subtree(
                hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Parameters");
            while (paramcount > 0) {
                proto_tree_add_item(hiqnet_parameters_tree, hf_hiqnet_paramid, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                if (flags & HIQNET_INFO_FLAG) { /* This is not a request */
                    offset = hiqnet_display_data(hiqnet_parameters_tree, tvb, offset);
                }
                paramcount -= 1;
            }
        }
        if (messageid == HIQNET_MULTPARMSET_MSG) {
            /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
            paramcount = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_paramcount, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            hiqnet_parameters_tree = proto_tree_add_subtree(
                hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Parameters");
            while (paramcount > 0) {
                proto_tree_add_item(hiqnet_parameters_tree, hf_hiqnet_paramid, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                offset = hiqnet_display_data(hiqnet_parameters_tree, tvb, offset);
                paramcount -= 1;
            }
        }
        if (messageid == HIQNET_PARMSUBALL_MSG) {
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_devaddr, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            /* TODO: decode VD-OBJECT */
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_vdobject, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            /* TODO: can be decoded in two ways (old and new) */
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_changetype, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_sensrate, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_initupd, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
        if (messageid == HIQNET_MULTPARMSUB_MSG) {
            /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
            subcount = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_subcount, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            hiqnet_subscriptions_tree = proto_tree_add_subtree(
                hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Subscriptions");
            while (subcount > 0) {
                offset = hiqnet_display_paramsub(hiqnet_subscriptions_tree, tvb, offset);
                subcount -= 1;
            }
        }
        if (messageid == HIQNET_GOODBYE_MSG) {
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_devaddr, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
        if (messageid == HIQNET_GETATTR_MSG) {
            attrcount = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_attrcount, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            if (flags & HIQNET_INFO_FLAG) { /* This not a request */
                hiqnet_attributes_tree = proto_tree_add_subtree(
                    hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Attributes");
                while (attrcount > 0) {
                    proto_tree_add_item(hiqnet_attributes_tree, hf_hiqnet_attrid, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    offset = hiqnet_display_data(hiqnet_attributes_tree, tvb, offset);
                    attrcount -= 1;
                }
            } else { /* This may be a request */
                while (attrcount > 0) {
                    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_attrid, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    attrcount -= 1;
                }
            }
        }
        if (messageid == HIQNET_GETVDLIST_MSG) {
            /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
            strlen = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_strlen, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_wrkgrppath, tvb, offset, strlen, ENC_UCS_2);
            offset += strlen;
            if (flags & HIQNET_INFO_FLAG) { /* This is not a request */
                vdscount = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_numvds, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                hiqnet_vds_tree = proto_tree_add_subtree(
                    hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Virtual Devices");
                while (vdscount > 0) {
                    proto_tree_add_item(hiqnet_vds_tree, hf_hiqnet_vdaddr, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                    proto_tree_add_item(hiqnet_vds_tree, hf_hiqnet_vdclassid, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    vdscount -= 1;
                }
            }
        }
        if (messageid == HIQNET_STORE_MSG) {
            /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_stract, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_strnum, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            strlen = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_strlen, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_wrkgrppath, tvb, offset, strlen, ENC_UCS_2);
            offset += strlen;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_scope, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        }
        if (messageid == HIQNET_RECALL_MSG) {
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_recact, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_recnum, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            strlen = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_strlen, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_wrkgrppath, tvb, offset, strlen, ENC_UCS_2);
            offset += strlen;
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_scope, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        }
        if (messageid == HIQNET_LOCATE_MSG) {
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_time, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            offset = hiqnet_display_sernum(hiqnet_payload_tree, tvb, offset);
        }
        if (messageid == HIQNET_SUBEVTLOGMSGS_MSG) {
            /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_maxdatasize, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            cats = tvb_get_ntohl(tvb, offset);
            hiqnet_cats_item = proto_tree_add_item(
                hiqnet_payload_tree, hf_hiqnet_catfilter, tvb, offset, 4, ENC_BIG_ENDIAN);
            hiqnet_decode_cats(cats, hiqnet_cats_item);
            hiqnet_display_cats(cats, hiqnet_cats_item, tvb, offset);
            offset += 4;
        }
        if (messageid == HIQNET_UNSUBEVTLOGMSGS_MSG) {
            /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
            cats = tvb_get_ntohl(tvb, offset);
            hiqnet_cats_item = proto_tree_add_item(
                hiqnet_payload_tree, hf_hiqnet_catfilter, tvb, offset, 4, ENC_BIG_ENDIAN);
            hiqnet_decode_cats(cats, hiqnet_cats_item);
            hiqnet_display_cats(cats, hiqnet_cats_item, tvb, offset);
            offset += 4;
        }
        if (messageid == HIQNET_REQEVTLOG_MSG) {
            /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
            if (flags & HIQNET_INFO_FLAG) { /* This is not a request */
                entriescount = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_entrieslen, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                hiqnet_events_tree = proto_tree_add_subtree(
                    hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Events");
                while (entriescount > 0) {
                    proto_tree_add_item(hiqnet_events_tree, hf_hiqnet_category, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(hiqnet_events_tree, hf_hiqnet_eventid, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(hiqnet_events_tree, hf_hiqnet_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                    proto_tree_add_item(hiqnet_events_tree, hf_hiqnet_eventseqnum, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    strlen = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_item(hiqnet_events_tree, hf_hiqnet_eventtime, tvb, offset, strlen, ENC_UCS_2);
                    offset += strlen;
                    strlen = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_item(hiqnet_events_tree, hf_hiqnet_eventdate, tvb, offset, strlen, ENC_UCS_2);
                    offset += strlen;
                    strlen = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_item(hiqnet_events_tree, hf_hiqnet_eventinfo, tvb, offset, strlen, ENC_UCS_2);
                    offset += strlen;
                    strlen = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_item(
                        hiqnet_events_tree, hf_hiqnet_eventadddata, tvb, offset, strlen, ENC_BIG_ENDIAN);
                    offset += strlen;
                    entriescount -= 1;
                }
            }
        }
        if (messageid == HIQNET_MULTPARMUNSUB_MSG) {
            /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
            subcount = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_subcount, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            hiqnet_subscriptions_tree = proto_tree_add_subtree(
                hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Subscriptions");
            while (subcount > 0) {
                proto_tree_add_item(hiqnet_subscriptions_tree, hf_hiqnet_pubparmid, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(hiqnet_subscriptions_tree, hf_hiqnet_subparmid, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                subcount -= 1;
            }
        }
        if (messageid == HIQNET_MULTOBJPARMSET_MSG) {
            /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
            objcount = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_objcount, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            hiqnet_objects_tree = proto_tree_add_subtree(
                hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Objects");
            while (objcount > 0) {
                proto_tree_add_item(hiqnet_objects_tree, hf_hiqnet_objdest, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                paramcount = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(hiqnet_objects_tree, hf_hiqnet_paramcount, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                hiqnet_parameters_tree = proto_tree_add_subtree(
                    hiqnet_objects_tree, tvb, offset, -1, ett_hiqnet, NULL, "Parameters");
                while (paramcount > 0) {
                    proto_tree_add_item(hiqnet_parameters_tree, hf_hiqnet_paramid, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    offset = hiqnet_display_data(hiqnet_parameters_tree, tvb, offset);
                    paramcount -= 1;
                }
            objcount -= 1;
            }
        }
        if (messageid == HIQNET_PARMSETPCT_MSG) {
            /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
            paramcount = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_paramcount, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            hiqnet_parameters_tree = proto_tree_add_subtree(
                hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Parameters");
            while (paramcount > 0) {
                proto_tree_add_item(hiqnet_parameters_tree, hf_hiqnet_paramid, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* TODO: docode paramval is in percentage represented as a 1.15 signed fixed point format */
                proto_tree_add_item(hiqnet_parameters_tree, hf_hiqnet_paramval, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                paramcount -= 1;
            }
        }
        if (messageid == HIQNET_PARMSUBPCT_MSG) {
            /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
            subcount = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_subcount, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            hiqnet_subscriptions_tree = proto_tree_add_subtree(
                hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Subscriptions");
            while (subcount > 0) {
                offset = hiqnet_display_paramsub(hiqnet_subscriptions_tree, tvb, offset);
                subcount -= 1;
            }
        }
        if (messageid == HIQNET_GETNETINFO_MSG) {
            /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
            offset = hiqnet_display_sernum(hiqnet_payload_tree, tvb, offset);
            if (flags & HIQNET_INFO_FLAG) { /* This is not a request */
                ifacecount = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_ifacecount, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                hiqnet_ifaces_tree = proto_tree_add_subtree(
                    hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Interfaces");
                while (ifacecount > 0) {
                    proto_tree_add_item(hiqnet_ifaces_tree, hf_hiqnet_maxmsgsize, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    offset = hiqnet_display_netinfo(hiqnet_ifaces_tree, tvb, offset);
                    ifacecount -= 1;
                }
            }
        }
        if (messageid == HIQNET_REQADDR_MSG) {
            /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_devaddr, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
        if (messageid == HIQNET_SETADDR_MSG) {
            offset = hiqnet_display_sernum(hiqnet_payload_tree, tvb, offset);
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_newdevaddr, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            offset = hiqnet_display_netinfo(hiqnet_payload_tree, tvb, offset);
        }
        if (messageid == HIQNET_SETATTR_MSG) { /* Reverse engineered. Not part of the official spec. */
            attrcount = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_attrcount, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            hiqnet_attributes_tree = proto_tree_add_subtree(
                hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Attributes");
            while (attrcount > 0) {
                proto_tree_add_item(hiqnet_attributes_tree, hf_hiqnet_attrid, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                offset = hiqnet_display_data(hiqnet_attributes_tree, tvb, offset);
                attrcount -= 1;
            }
        }
    }
}


gint
hiqnet_display_netinfo(proto_tree *hiqnet_payload_tree, tvbuff_t *tvb, gint offset) {
    guint netid = 0;
    netid = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_netid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    if (netid == HIQNET_TCPIP_NET) {
            offset = hiqnet_display_tcpipnetinfo(hiqnet_payload_tree, tvb, offset);
    }
    if (netid == HIQNET_RS232_NET) {
        offset = hiqnet_display_rs232netinfo(hiqnet_payload_tree, tvb, offset);
    }
    return offset;
}


gint
hiqnet_display_tcpipnetinfo(proto_tree *hiqnet_payload_tree, tvbuff_t *tvb, gint offset) {
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
    return offset;
}


gint
hiqnet_display_rs232netinfo(proto_tree *hiqnet_payload_tree, tvbuff_t *tvb, gint offset) {
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_comid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_baudrate, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_parity, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_stopbits, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_databits, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_flowcontrol, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    return offset;
}


gint
hiqnet_display_sernum(proto_tree *hiqnet_payload_tree, tvbuff_t *tvb, gint offset) {
    gint strlen;
    strlen = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_sernumlen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_sernum, tvb, offset, strlen, ENC_BIG_ENDIAN);
    offset += strlen;
    return offset;
}


gint
hiqnet_display_paramsub(proto_tree *hiqnet_payload_tree, tvbuff_t *tvb, gint offset) {
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_pubparmid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_subaddr, tvb, offset, 6, ENC_BIG_ENDIAN);
    offset += 6;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_subparmid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_reserved0, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_reserved1, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_sensrate, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    return offset;
}


gint
hiqnet_display_data(proto_tree *hiqnet_payload_tree, tvbuff_t *tvb, gint offset) {
    guint8 datatype = 0;
    gint datalen;

    datatype = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_datatype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    datalen = hiqnet_datasize_per_type[datatype];
    if (datalen < 0) { /* This is a string or a block */
        datalen = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_datalen, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }
    if (datatype == 9) { /* This is a string */
        proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_string, tvb, offset, datalen, ENC_UCS_2);
    } else {
        proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_value, tvb, offset, datalen, ENC_BIG_ENDIAN);
    }
    offset += datalen;
    return offset;
}


void
hiqnet_decode_flags(guint16 flags, proto_item *hiqnet_flags) { /* Message for enabled flags */
    if (flags & HIQNET_REQACK_FLAG) {
            proto_item_append_text(hiqnet_flags, ", %s",
                try_val_to_str(HIQNET_REQACK_FLAG, flagnames));
        }
    if (flags & HIQNET_ACK_FLAG) {
            proto_item_append_text(hiqnet_flags, ", %s",
                try_val_to_str(HIQNET_ACK_FLAG, flagnames));
        }
    if (flags & HIQNET_INFO_FLAG) {
            proto_item_append_text(hiqnet_flags, ", %s",
                try_val_to_str(HIQNET_INFO_FLAG, flagnames));
        }
    if (flags & HIQNET_ERROR_FLAG) {
            proto_item_append_text(hiqnet_flags, ", %s",
                try_val_to_str(HIQNET_ERROR_FLAG, flagnames));
        }
    if (flags & HIQNET_GUARANTEED_FLAG) {
            proto_item_append_text(hiqnet_flags, ", %s",
                try_val_to_str(HIQNET_GUARANTEED_FLAG, flagnames));
        }
    if (flags & HIQNET_MULTIPART_FLAG) {
            proto_item_append_text(hiqnet_flags, ", %s",
                try_val_to_str(HIQNET_MULTIPART_FLAG, flagnames));
        }
    if (flags & HIQNET_SESSION_FLAG) {
            proto_item_append_text(hiqnet_flags, ", %s",
                val_to_str(HIQNET_SESSION_FLAG, flagnames, "Unknown"));
        }
}


void
hiqnet_display_flags(guint16 flags, proto_item *hiqnet_flags_item, tvbuff_t *tvb, gint offset) {
    proto_tree *hiqnet_flags_tree = NULL;
    if (flags) {
        hiqnet_flags_tree = proto_item_add_subtree(hiqnet_flags_item, ett_hiqnet_flags);
        proto_tree_add_item(hiqnet_flags_tree, hf_hiqnet_reqack_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(hiqnet_flags_tree, hf_hiqnet_ack_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(hiqnet_flags_tree, hf_hiqnet_info_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(hiqnet_flags_tree, hf_hiqnet_error_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(hiqnet_flags_tree, hf_hiqnet_guaranteed_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(hiqnet_flags_tree, hf_hiqnet_multipart_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(hiqnet_flags_tree, hf_hiqnet_session_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
    }
}


void
hiqnet_display_cats(guint32 cats, proto_item *hiqnet_cats_item, tvbuff_t *tvb, gint offset) {
    proto_tree *hiqnet_cats_tree = NULL;
    if (cats) {
        hiqnet_cats_tree = proto_item_add_subtree(hiqnet_cats_item, ett_hiqnet_cats);
        proto_tree_add_item(hiqnet_cats_tree, hf_hiqnet_app_cat, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(hiqnet_cats_tree, hf_hiqnet_conf_cat, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(hiqnet_cats_tree, hf_hiqnet_audionet_cat, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(hiqnet_cats_tree, hf_hiqnet_ctrlnet_cat, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(hiqnet_cats_tree, hf_hiqnet_vendnet_cat, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(hiqnet_cats_tree, hf_hiqnet_startup_cat, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(hiqnet_cats_tree, hf_hiqnet_dsp_cat, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(hiqnet_cats_tree, hf_hiqnet_misc_cat, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(hiqnet_cats_tree, hf_hiqnet_ctrlog_cat, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(hiqnet_cats_tree, hf_hiqnet_foreignproto_cat, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(hiqnet_cats_tree, hf_hiqnet_digio_cat, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(hiqnet_cats_tree, hf_hiqnet_ctrlsurf_cat, tvb, offset, 2, ENC_BIG_ENDIAN);
    }
}


void
hiqnet_decode_cats(guint32 cats, proto_item *hiqnet_cats) {
    if (cats & HIQNET_APPLICATION_CAT) {
        proto_item_append_text(hiqnet_cats, ", %s",
            try_val_to_str(HIQNET_APPLICATION_CAT, eventcategorynames));
    }
    if (cats & HIQNET_CONF_CAT) {
        proto_item_append_text(hiqnet_cats, ", %s",
            try_val_to_str(HIQNET_CONF_CAT, eventcategorynames));
    }
    if (cats & HIQNET_AUDIONET_CAT) {
        proto_item_append_text(hiqnet_cats, ", %s",
            try_val_to_str(HIQNET_AUDIONET_CAT, eventcategorynames));
    }
    if (cats & HIQNET_CTRLNET_CAT) {
        proto_item_append_text(hiqnet_cats, ", %s",
            try_val_to_str(HIQNET_CTRLNET_CAT, eventcategorynames));
    }
    if (cats & HIQNET_VENDNET_CAT) {
        proto_item_append_text(hiqnet_cats, ", %s",
            try_val_to_str(HIQNET_VENDNET_CAT, eventcategorynames));
    }
    if (cats & HIQNET_STARTUP_CAT) {
        proto_item_append_text(hiqnet_cats, ", %s",
            try_val_to_str(HIQNET_STARTUP_CAT, eventcategorynames));
    }
    if (cats & HIQNET_DSP_CAT) {
        proto_item_append_text(hiqnet_cats, ", %s",
            try_val_to_str(HIQNET_DSP_CAT, eventcategorynames));
    }
    if (cats & HIQNET_MISC_CAT) {
        proto_item_append_text(hiqnet_cats, ", %s",
            try_val_to_str(HIQNET_MISC_CAT, eventcategorynames));
    }
    if (cats & HIQNET_CTRLLOG_CAT) {
        proto_item_append_text(hiqnet_cats, ", %s",
            try_val_to_str(HIQNET_CTRLLOG_CAT, eventcategorynames));
    }
    if (cats & HIQNET_FOREIGNPROTO_CAT) {
        proto_item_append_text(hiqnet_cats, ", %s",
            try_val_to_str(HIQNET_FOREIGNPROTO_CAT, eventcategorynames));
    }
    if (cats & HIQNET_DIGIO_CAT) {
        proto_item_append_text(hiqnet_cats, ", %s",
            try_val_to_str(HIQNET_DIGIO_CAT, eventcategorynames));
    }
    if (cats & HIQNET_CTRLSURF_CAT) {
        proto_item_append_text(hiqnet_cats, ", %s",
            try_val_to_str(HIQNET_CTRLSURF_CAT, eventcategorynames));
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
                FT_STRINGZ, STR_UNICODE,
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
                VALS(networknames), 0x0,
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
        },
        { &hf_hiqnet_paramcount,
            { "Parameter count", "hiqnet.paramcount",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_paramid,
            { "Parameter ID", "hiqnet.paramid",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_datatype,
            { "Data type", "hiqnet.datatype",
                FT_UINT8, BASE_HEX,
                VALS(datatypenames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_value,
            { "Value", "hiqnet.value",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_vdobject,
            { "Virtual Device Object", "hiqnet.vdobject",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_changetype,
            { "Change Type", "hiqnet.changetype",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_sensrate,
            { "Sensor Rate (ms)", "hiqnet.sensrate",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_initupd,
            { "Initial Update", "hiqnet.initupd",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_subcount,
            { "No of Subscriptions", "hiqnet.subcount",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_pubparmid,
            { "Publisher Parameter ID", "hiqnet.pubparmid",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_subtype,
            { "Subscription Type", "hiqnet.subtype",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_subaddr,
            { "Subscriber Address", "hiqnet.subaddr",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_subparmid,
            { "Subscriber Parameter ID", "hiqnet.subparmid",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_reserved0,
            { "Reserved", "hiqnet.reserved0",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_reserved1,
            { "Reserved", "hiqnet.reserved1",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_attrcount,
            { "Attribute count", "hiqnet.attrcount",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_attrid,
            { "Attribute ID", "hiqnet.attrid",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_datalen,
            { "Data lenght", "hiqnet.datalen",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_string,
            { "String", "hiqnet.string",
                FT_STRINGZ, STR_UNICODE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_wrkgrppath,
            { "Workgroup Path", "hiqnet.wrkgrppath",
                FT_STRINGZ, STR_UNICODE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_numvds,
            { "Number of Virtual Devices", "hiqnet.numvds",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_vdaddr,
            { "Virtual Device Address", "hiqnet.vdaddr",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_vdclassid,
            { "Virtual Device Class ID", "hiqnet.vdclassid",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_stract,
            { "Store Action", "hiqnet.stract",
                FT_UINT8, BASE_DEC,
                VALS(actionnames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_strnum,
            { "Store Number", "hiqnet.strnum",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_scope,
            { "Scope", "hiqnet.scope",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_recact,
            { "Recall Action", "hiqnet.rec.act",
                FT_UINT8, BASE_DEC,
                VALS(actionnames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_recnum,
            { "Recall Number", "hiqnet.recnum",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_strlen,
            { "String lenght", "hiqnet.strlen",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_time,
            { "Locate time (ms)", "hiqnet.time",
                FT_UINT16, BASE_DEC,
                VALS(timenames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_maxdatasize,
            { "Maximum Data Size", "hiqnet.maxdatasize",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_catfilter,
            { "Category Filter", "hiqnet.catfilter",
                FT_UINT32, BASE_DEC,
                NULL, HIQNET_CATEGORIES_MASK,
                NULL, HFILL }
        },
        { &hf_hiqnet_app_cat,
            { "Application Category", "hiqnet.appcat",
                FT_UINT32, BASE_HEX,
                NULL, HIQNET_APPLICATION_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_conf_cat,
            { "Configuration Category", "hiqnet.confcat",
                FT_UINT32, BASE_HEX,
                NULL, HIQNET_CONF_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_audionet_cat,
            { "Audio Network Category", "hiqnet.audionetcat",
                FT_UINT32, BASE_HEX,
                NULL, HIQNET_AUDIONET_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_ctrlnet_cat,
            { "Control Network Category", "hiqnet.ctrlnetcat",
                FT_UINT32, BASE_HEX,
                NULL, HIQNET_CTRLNET_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_vendnet_cat,
            { "Vendor Network Category", "hiqnet.vendnetcat",
                FT_UINT32, BASE_HEX,
                NULL, HIQNET_VENDNET_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_startup_cat,
            { "Startup Category", "hiqnet.startupcat",
                FT_UINT32, BASE_HEX,
                NULL, HIQNET_STARTUP_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_dsp_cat,
            { "DSP Category", "hiqnet.dspcat",
                FT_UINT32, BASE_HEX,
                NULL, HIQNET_DSP_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_misc_cat,
            { "Miscellenaous Category", "hiqnet.misccat",
                FT_UINT32, BASE_HEX,
                NULL, HIQNET_MISC_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_ctrlog_cat,
            { "Control Logic Category", "hiqnet.crtllogcat",
                FT_UINT32, BASE_HEX,
                NULL, HIQNET_CTRLLOG_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_foreignproto_cat,
            { "Foreign Protocol Category", "hiqnet.foreignprotocat",
                FT_UINT32, BASE_HEX,
                NULL, HIQNET_FOREIGNPROTO_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_digio_cat,
            { "Digital I/O Category", "hiqnet.digiocat",
                FT_UINT32, BASE_HEX,
                NULL, HIQNET_DIGIO_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_ctrlsurf_cat,
            { "Control Surface Category", "hiqnet.ctrlsurfcat",
                FT_UINT32, BASE_HEX,
                NULL, HIQNET_CTRLSURF_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_entrieslen,
            { "Number of Entries", "hiqnet.entrieslen",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_category,
            { "Category", "hiqnet.cat",
                FT_UINT16, BASE_HEX,
                VALS(eventcategorynames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_eventid,
            { "Event ID", "hiqnet.eventid",
                FT_UINT16, BASE_DEC,
                VALS(eventidnames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_priority,
            { "Priority", "hiqnet.priority",
                FT_UINT8, BASE_DEC,
                VALS(prioritynames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_eventseqnum,
            { "Sequence Number", "hiqnet.eventseqnum",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_eventtime,
            { "Time", "hiqnet.eventtime",
                FT_STRING, STR_UNICODE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_eventdate,
            { "Date", "hiqnet.eventdate",
                FT_STRING, STR_UNICODE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_eventinfo,
            { "Information", "hiqnet.information",
                FT_STRING, STR_UNICODE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_eventadddata,
            { "Additional Data", "hiqnet.eventadddata",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_objcount,
            { "Object Count", "hiqnet.objcount",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_objdest,
            { "Object Dest", "hiqnet.objdest",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_paramval,
            { "Parameter Value (%)", "hiqnet.paramval",
                FT_INT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_ifacecount,
            { "Interface Count", "hiqnet.ifacecount",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_comid,
            { "Com Port Identifier", "hiqnet.comid",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_baudrate,
            { "Baud Rate", "hiqnet.baudrate",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_parity,
            { "Parity", "hiqnet.parity",
                FT_UINT8, BASE_DEC,
                VALS(paritynames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_stopbits,
            { "Stop Bits", "hiqnet.stopbits",
                FT_UINT8, BASE_DEC,
                VALS(stopbitsnames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_databits,
            { "Data Bits", "hiqnet.databits",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_flowcontrol,
            { "Flowcontrol", "hiqnet.flowcontrol",
                FT_UINT8, BASE_DEC,
                VALS(flowcontrolnames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_devaddr,
            { "Device Address", "hiqnet.devaddr",
                FT_UINT16, BASE_DEC_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_newdevaddr,
            { "New Device Address", "hiqnet.newdevaddr",
                FT_UINT16, BASE_DEC_HEX,
                NULL, 0x0,
                NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_hiqnet,
        &ett_hiqnet_flags,
        &ett_hiqnet_cats
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
