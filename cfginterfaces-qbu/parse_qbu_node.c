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
			str_del_last_key(node_path);
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
			strcat(node_path, "/");
			strcat(node_path, content);
			break;
		}
	}

	for (tmp_node = tmp_node->children; tmp_node != NULL;
	     tmp_node = tmp_node->next) {
		if (tmp_node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)tmp_node->name;
		if (strcmp(content, "frame-preemption-status-table") == 0) {
			strcpy(path, node_path);
			strcat(path, "/");
			strcat(path, content);
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

void get_qbu_st_xml(xmlNodePtr xml_node, struct tsn_preempt_status *pts)
{
	xmlNodePtr qbu_node;
	char valstr[32];
	xmlNsPtr ns;

	nc_verb_verbose("%s is called", __func__);
	if (!pts->preemption_active)
		return;
	qbu_node = xmlNewChild(xml_node, NULL,
				     BAD_CAST "frame-preemption-parameters",
				     NULL);
	ns = xmlNewNs(qbu_node, BAD_CAST QBU_NS, BAD_CAST QBU_PREFIX);
	xmlSetNs(qbu_node, ns);
	sprintf(valstr, "%d", pts->hold_advance);
	xmlNewTextChild(qbu_node, NULL, BAD_CAST "hold-advance",
			BAD_CAST valstr);
	sprintf(valstr, "%d", pts->release_advance);
	xmlNewTextChild(qbu_node, NULL, BAD_CAST "release-advance",
			BAD_CAST valstr);
	if (pts->preemption_active)
		xmlNewTextChild(qbu_node, NULL, BAD_CAST "preemption-active",
				BAD_CAST "true");
	else
		xmlNewTextChild(qbu_node, NULL, BAD_CAST "preemption-active",
				BAD_CAST "false");
	if (pts->hold_request == 1)
		xmlNewTextChild(qbu_node, NULL, BAD_CAST "hold-request",
				BAD_CAST "hold");
	if (pts->hold_request == 2)
		xmlNewTextChild(qbu_node, NULL, BAD_CAST "hold-request",
				BAD_CAST "release");
}

void get_qbu_cfg_xml(xmlNodePtr xml_node, int pts)
{
	int i;
	xmlNodePtr table;
	xmlNodePtr qbu_node;
	char valstr[32];
	uint32_t preemp_st = 0;
	xmlNsPtr ns;

	nc_verb_verbose("%s is called", __func__);
	qbu_node = xmlNewChild(xml_node, NULL,
				     BAD_CAST "frame-preemption-parameters",
				     NULL);
	ns = xmlNewNs(qbu_node, BAD_CAST QBU_NS, BAD_CAST QBU_PREFIX);
	xmlSetNs(qbu_node, ns);
	for (i = 0; i < 8; i++) {
		table = xmlNewChild(qbu_node, NULL,
				    BAD_CAST "frame-preemption-status-table",
				    NULL);
		sprintf(valstr, "%d", i);
		xmlNewTextChild(table, NULL,
				BAD_CAST "traffic-class", BAD_CAST valstr);
		preemp_st = (pts & (1<<i));
		if (preemp_st)
			sprintf(valstr, "preemptable");
		else
			sprintf(valstr, "express");
		xmlNewTextChild(table, NULL,
				BAD_CAST "frame-preemption-status",
				BAD_CAST valstr);

	}
}

int get_qbu_from_json(struct tsn_preempt_status *pts)
{
	int rc = EXIT_SUCCESS;
	FILE *fp;
	cJSON *json, *item;
	char *json_data;
	int len;

	fp = fopen(TSNTOOL_PORT_ST_FILE, "r");
	if (!fp) {
		nc_verb_verbose("open '%s' error", TSNTOOL_PORT_ST_FILE);
		rc = EXIT_FAILURE;
		goto out;
	}

	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	json_data = (char *)malloc(len+1);
	if (!json_data) {
		fclose(fp);
		nc_verb_verbose("malloc error");
		rc = EXIT_FAILURE;
		goto out;
	}

	fread(json_data, 1, len, fp);
	json = cJSON_Parse(json_data);
	if (!json) {
		nc_verb_verbose("json parse error");
		free(json_data);
		fclose(fp);
		rc = EXIT_FAILURE;
		goto out;
	}
	item = cJSON_GetObjectItem(json, "preemtable");
	if (item)
		pts->admin_state = (uint8_t)item->valuedouble;
	else
		rc = EXIT_FAILURE;
	item = cJSON_GetObjectItem(json, "holdadvance");
	if (item)
		pts->hold_advance = (uint32_t)item->valuedouble;
	item = cJSON_GetObjectItem(json, "releaseadvance");
	if (item)
		pts->release_advance = (uint32_t)item->valuedouble;
	item = cJSON_GetObjectItem(json, "active");
	if (item)
		pts->preemption_active = 1;
	else
		pts->preemption_active = 0;
	item = cJSON_GetObjectItem(json, "holdrequest");
	if (item)
		pts->hold_request = (uint8_t)item->valuedouble;

	cJSON_Delete(json);
	free(json_data);
	fclose(fp);
out:
	return rc;
}
int get_qbu_info(char *port, xmlNodePtr node, int mode)
{
	int rc;
	struct tsn_preempt_status pts;

	init_tsn_socket();
	rc = tsn_qbu_get_status(port, &pts);
	close_tsn_socket();
	if (rc < 0)
		return rc;

	rc = get_qbu_from_json(&pts);
	if (rc == EXIT_FAILURE)
		return rc;

	if (mode)
		get_qbu_cfg_xml(node, pts.admin_state);
	else
		get_qbu_st_xml(node, &pts);
	return EXIT_SUCCESS;
}
