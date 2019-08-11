/*
 * SPDX-License-Identifier:	(GPL-2.0 OR MIT)
 *
 * Copyright 2019 NXP
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <libxml/tree.h>
#include <libnetconf_xml.h>
#include <pthread.h>
#include <semaphore.h>
#include <tsn/genl_tsn.h>
#include <linux/tsn.h>
#include <cjson/cJSON.h>
#include "platform.h"
#include "interfaces.h"
#include "parse_qbu_node.h"
#include "xml_node_access.h"

int parse_preempt_st_table(xmlNode *node,
	struct std_qbu_conf *qbu_conf, char *err_msg, char *node_path)
{
	int rc = EXIT_SUCCESS;
	char *content;
	uint32_t traffic_class = 0;
	unsigned long tmp;
	xmlNode *tmp_node;
	char ele_val[MAX_ELEMENT_LENGTH];

	nc_verb_verbose("%s is called", __func__);

	tmp_node = node->children;
	for (tmp_node = node->children;
	     tmp_node != NULL; tmp_node = tmp_node->next) {
		if (tmp_node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)tmp_node->name;
		if (strcmp(content, "traffic-class") == 0) {
			rc = xml_read_field(tmp_node, "traffic-class",
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			tmp = strtoul(ele_val, NULL, 0);
			traffic_class = (uint8_t)tmp;
			strcat(node_path, "(");
			strcat(node_path, ele_val);
			strcat(node_path, ")");
			if (traffic_class > 7) {
				sprintf(err_msg,
					"'%s':%d in '%s' is out of range!",
					content,
					traffic_class, node_path);
				rc = EXIT_FAILURE;
				goto out;
			}
		} else if (strcmp(content, "frame-preemption-status") == 0) {
			rc = xml_read_field(tmp_node, "frame-preemption-status",
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			if (strcmp(ele_val, "express") == 0) {
				qbu_conf->pt_vector &=  ~(1<<traffic_class);
			} else if (strcmp(ele_val, "preemptable") == 0) {
				qbu_conf->pt_vector ^=  (1<<traffic_class);
			} else {
				sprintf(err_msg, "'%s' in %s is out of range!",
				ele_val, node_path);
				rc = EXIT_FAILURE;
				goto out;
			}
		} else {
			sprintf(err_msg, "unknown node '%s' in path '%s'!",
				ele_val, node_path);
			rc = EXIT_FAILURE;
			goto out;
		}
	}
out:
	return rc;
}

int parse_qbu_node(xmlNode *node, struct std_qbu_conf *qbu_conf,
			  char *err_msg, char *node_path)

{
	int rc = EXIT_SUCCESS;
	char *content;
	xmlNode *tmp_node = node;
	char path[MAX_PATH_LENGTH];

	nc_verb_verbose("%s is called", __func__);

	qbu_conf->pt_vector = 0;

	for (tmp_node = node->children; tmp_node != NULL;
	     tmp_node = tmp_node->next) {
		if (tmp_node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)tmp_node->name;
		if (strcmp(content, "frame-preemption-parameters") == 0) {
			strcpy(path, node_path);
			strcat(path, "/frame-preemption-parameters");
			break;
		}
	}

	for (tmp_node = tmp_node->children; tmp_node != NULL;
	     tmp_node = tmp_node->next) {
		if (tmp_node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)tmp_node->name;
		if (strcmp(content, "frame-preemption-status-table") == 0) {
			strcat(path, "/frame-preemption-status-table");
			rc = parse_preempt_st_table(tmp_node, qbu_conf,
						    err_msg, path);
			if (rc != EXIT_SUCCESS)
				goto out;
		} else {
			sprintf(err_msg, "unknown node '%s' in path '%s'!",
				content, node_path);
			rc = EXIT_FAILURE;
			goto out;
		}
	}

out:
	return rc;
}


int probe_qbu_xml_from_json(xmlNodePtr xml_node, cJSON *json_ob)
{
	return EXIT_SUCCESS;
}

int get_qbu_status(char *port, xmlNodePtr node)
{
	return EXIT_SUCCESS;
}


