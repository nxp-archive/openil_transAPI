/*
 * SPDX-License-Identifier:	(GPL-2.0 OR MIT)
 *
 * Copyright 2019 NXP
 */
#include <libxml/tree.h>
#include "platform.h"
#ifndef __XML_NODE_ACCESS_H__
#define __XML_NODE_ACCESS_H__

enum num_type {
	NUM_TYPE_S8 =  0x1,
	NUM_TYPE_U8 =  0x2,
	NUM_TYPE_S16 =  0x3,
	NUM_TYPE_U16 =  0x4,
	NUM_TYPE_S32 =  0x5,
	NUM_TYPE_U32 =  0x6,
	NUM_TYPE_S64 =  0x7,
	NUM_TYPE_U64 =  0x8,
};

int xml_read_field(xmlNode *node, char *field_name, char *data,
		char *err_msg, char *node_path);
xmlNodePtr get_child_node(xmlNodePtr parent_node, const char *child_node_name);
xmlNodePtr create_root_in_doc(xmlDocPtr doc, char *rootname, char *ns);
xmlNodePtr create_root_in_doc_no_ns(xmlDocPtr doc, char *rootname);
void free_doc_mem(xmlDocPtr doc);
void prt_err_bool(char *err_msg, char *name, char *path);
int get_cycle_time(xmlNode *node, uint32_t *cycle_time, char *err_msg,
		char *node_path);
void str_del_last_key(char *str);
int str_to_num(char *node_name, int type, char *str, uint64_t *num,
		char *err_msg, char *node_path);
#endif
