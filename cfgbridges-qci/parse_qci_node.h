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

#ifndef __PARSE_QCI_NODE_H__
#define __PARSE_QCI_NODE_H__

struct std_qci_psfp_sfi {
	uint32_t stream_filter_instance_id;
	bool enable;
	struct tsn_qci_psfp_sfi_conf sficonf;
};

struct std_qci_psfp_sfi_table {
	struct std_qci_psfp_sfi *sfi_ptr;
	struct std_qci_psfp_sfi_table *next;
};

struct std_qci_psfp_sgi {
	uint32_t sgi_handle;
	bool enable;
	struct tsn_qci_psfp_sgi_conf sgiconf;
};

struct std_qci_psfp_sgi_table {
	struct std_qci_psfp_sgi *sgi_ptr;
	struct std_qci_psfp_sgi_table *next;
};

struct std_qci_psfp_fmi {
	uint32_t fmi_id;
	bool enable;
	struct tsn_qci_psfp_fmi fmiconf;
};

struct std_qci_psfp_fmi_table {
	struct std_qci_psfp_fmi *fmi_ptr;
	struct std_qci_psfp_fmi_table *next;
};

struct std_qci_conf {
	char device_name[MAX_IF_NAME_LENGTH];
	struct std_qci_psfp_sfi_table *sfi_table;
	struct std_qci_psfp_sgi_table *sgi_table;
	struct std_qci_psfp_fmi_table *fmi_table;
};

int get_qci_status(char *port, xmlNodePtr node);
int parse_stream_filters(xmlNode *node, struct std_qci_conf *qci_conf,
				   char *err_msg, char *node_path);
int parse_stream_gates(xmlNode *node, struct std_qci_conf *qci_conf,
				char *err_msg, char *node_path);
int parse_flow_meters(xmlNode *node, struct std_qci_conf *qci_conf,
			       char *err_msg, char *node_path);
void init_qci_memory(struct std_qci_conf *qci_conf);
void free_qci_memory(struct std_qci_conf *qci_conf);
#endif
