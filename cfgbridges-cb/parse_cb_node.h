/*
 * SPDX-License-Identifier:	(GPL-2.0 OR MIT)
 *
 * Copyright 2019 NXP
 */
#include <tsn/genl_tsn.h>
#include <linux/tsn.h>
#include <libxml/tree.h>
#include <libnetconf_xml.h>
#include <platform.h>

#ifndef __PARSE_CB_NODE_H__
#define __PARSE_CB_NODE_H__

struct std_cb_stream {
	uint32_t index;
	bool enable;
	struct tsn_cb_streamid cbconf;
};
struct std_cb_stream_table {
	struct std_cb_stream *stream_ptr;
	struct std_cb_stream_table *next;
};
struct std_cb_conf {
	char device_name[MAX_IF_NAME_LENGTH];
	struct std_cb_stream_table *stream_table;
};
struct ip_addr {
	uint8_t version; //1:ipv4 2:ipv6
	uint64_t iph;
	uint64_t ipl;
};
int cbstreamid_handle(char *portname, xmlNode *node,
		char *err_msg, char *node_path);
int get_cb_info(char *port, xmlNodePtr node, int mode, uint32_t index);
#endif
