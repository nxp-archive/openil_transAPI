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

#ifndef __PARSE_QBU_NODE_H__
#define __PARSE_QBU_NODE_H__

struct std_qbu_conf {
	char device_name[MAX_IF_NAME_LENGTH];
	uint8_t pt_vector;
};

int get_qbu_info(char *port, xmlNodePtr node, int mode);
int parse_qbu_node(xmlNode *node, struct std_qbu_conf *qbu_conf,
			  char *err_msg, char *node_path);
#endif

