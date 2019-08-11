/*
 * SPDX-License-Identifier:	(GPL-2.0 OR MIT)
 *
 * Copyright 2019 NXP
 */
#include <libxml/tree.h>
#ifndef __XML_NODE_ACCESS_H__
#define __XML_NODE_ACCESS_H__

int xml_read_field(xmlNode *node, char *field_name, char *data,
			  char *err_msg, char *node_path);
xmlNodePtr get_child_node(xmlNodePtr parent_node, const char *child_node_name);
xmlNodePtr create_root_in_doc(xmlDocPtr doc, char *rootname, char *ns);
xmlNodePtr create_root_in_doc_no_ns(xmlDocPtr doc, char *rootname);
void free_doc_mem(xmlDocPtr doc);
void prt_err_bool(char *err_msg, char *name, char *path);
#endif
