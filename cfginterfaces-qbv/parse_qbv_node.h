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

#ifndef __PARSE_QBV_NODE_H__
#define __PARSE_QBV_NODE_H__

struct std_qbv_conf {
	char device_name[MAX_IF_NAME_LENGTH];
	struct tsn_qbv_conf qbv_conf;
};

int get_qbv_status(char *port, xmlNodePtr node);
int parse_qbv_node(xmlNode *node, struct std_qbv_conf *admin_conf,
	char *err_msg, char *node_path);

#endif

