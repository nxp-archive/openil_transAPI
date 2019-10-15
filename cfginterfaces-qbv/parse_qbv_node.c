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
#include "platform.h"
#include "interfaces.h"
#include "parse_qbv_node.h"
#include <cjson/cJSON.h>
#include "xml_node_access.h"
#include "json_node_access.h"

enum QBV_GET_RET {
	GET_SUCCESS,
	QBV_DISABLE,
	CFG_PEND,
	GET_FAIL,
};

int parse_sgs_params(xmlNode *node, struct std_qbv_conf *admin_conf,
	int list_index, char *err_msg, char *node_path)
{
	int rc = EXIT_SUCCESS;
	char *content;
	uint64_t tmp;
	char ele_val[MAX_ELEMENT_LENGTH];
	struct tsn_qbv_entry *entry;

	nc_verb_verbose("%s is called", __func__);

	entry = admin_conf->qbv_conf.admin.control_list;
	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)node->name;
		if (strcmp(content, "gate-states-value") == 0) {
			rc = xml_read_field(node, content, ele_val,
					    err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			rc = str_to_num(content, NUM_TYPE_U8, ele_val,
					&tmp, err_msg, node_path);
			if (rc < 0)
				goto out;
			(entry + list_index)->gate_state = (uint8_t)tmp;

		} else if (strcmp(content, "time-interval-value") == 0) {
			rc = xml_read_field(node, content, ele_val,
					    err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;
			rc = str_to_num(content, NUM_TYPE_U32, ele_val,
					&tmp, err_msg, node_path);
			if (rc < 0)
				goto out;

			(entry + list_index)->time_interval = (uint32_t)tmp;
		}
	}
out:
	return rc;
}

int qbv_parse_admin_base_time(xmlNode *node, struct std_qbv_conf *admin_conf,
	char *err_msg, char *node_path)
{
	int rc = EXIT_SUCCESS;
	char *content;
	uint64_t tmp;
	char ele_val[MAX_ELEMENT_LENGTH];
	struct ieee_ptp_time admin_base_time = {0, 0};

	nc_verb_verbose("%s is called", __func__);

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)node->name;
		if (strcmp(content, "seconds") == 0) {
			rc = xml_read_field(node, "seconds",
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			rc = str_to_num(content, NUM_TYPE_U32, ele_val,
					&tmp, err_msg, node_path);
			if (rc < 0)
				goto out;
			admin_base_time.seconds = (uint32_t) tmp;
		} else if (strcmp(content, "fractional-seconds") == 0) {
			rc = xml_read_field(node, "fractional-seconds",
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			rc = str_to_num(content, NUM_TYPE_U32, ele_val,
					&tmp, err_msg, node_path);
			if (rc < 0)
				goto out;
			admin_base_time.nano_seconds = (uint32_t) tmp;
		}
	}
	admin_conf->qbv_conf.admin.base_time = admin_base_time.nano_seconds + \
		(admin_base_time.seconds*1000000000);
	//nc_verb_verbose("base time is %lu", admin_conf->qbv_conf.admin.base_time);
out:
	return rc;
}


int qbv_parse_admin_control_list(xmlNode *node, struct std_qbv_conf *admin_conf,
	uint32_t list_index, char *err_msg, char *node_path)
{
	int rc = EXIT_SUCCESS;
	char *content;
	uint64_t tmp;
	xmlNode *tmp_node;
	char ele_val[MAX_ELEMENT_LENGTH];

	nc_verb_verbose("%s is called", __func__);

	tmp_node = node->children;

	for (tmp_node = node->children; tmp_node != NULL;
	     tmp_node = tmp_node->next) {
		if (tmp_node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)tmp_node->name;
		if (strcmp(content, "index") == 0) {
			rc = xml_read_field(tmp_node, "index",
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;
			str_del_last_key(node_path);
			strcat(node_path, "(");
			strcat(node_path, ele_val);
			strcat(node_path, ")");
			rc = str_to_num(content, NUM_TYPE_U32, ele_val,
					&tmp, err_msg, node_path);
			if (rc < 0)
				goto out;
			if ((uint32_t)tmp != list_index) {
				sprintf(err_msg,
					"'%s' in '%s' is not continuous!",
					content, node_path);
				rc = EXIT_FAILURE;
				goto out;
			}
		} else if (strcmp(content, "operation-name") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			if (strstr(ele_val, "set-gate-states")) {
				continue;
			} else if (strstr(ele_val, "set-and-hold-mac")){
				continue;
			} else if (strstr(ele_val, "set-and-release-mac")){
				continue;
			} else {
				sprintf(err_msg, "unknown '%s' in '%s'",
					ele_val, node_path);
				rc = EXIT_FAILURE;
				goto out;
			}
		} else if (strcmp(content, "sgs-params") == 0) {
			rc = parse_sgs_params(tmp_node, admin_conf,
					      list_index, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;
		}
	}
out:
	return rc;
}

int parse_max_sdu_table(xmlNode *node, struct std_qbv_conf *admin_conf,
	char *err_msg, char *node_path)
{
	int rc = EXIT_SUCCESS;
	uint32_t traffic_class_index = 0;
	char *content;
	xmlNode *tmp_node = node;
	uint64_t tmp;
	char ele_val[MAX_ELEMENT_LENGTH];

	nc_verb_verbose("%s is called", __func__);

	for (tmp_node = node->children; tmp_node != NULL;
	     tmp_node = tmp_node->next) {
		if (tmp_node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)tmp_node->name;
		if (strcmp(content, "traffic-class") == 0) {
			rc = xml_read_field(tmp_node, "traffic-class",
					    ele_val, err_msg, node_path);

			if (rc != EXIT_SUCCESS) {
				goto out;
			} else {
				str_del_last_key(node_path);
				strcat(node_path, "(");
				strcat(node_path, ele_val);
				strcat(node_path, ")");
				traffic_class_index++;
			}
		} else if (strcmp(content, "queue-max-sdu") == 0) {
			rc = xml_read_field(tmp_node, "queue-max-sdu",
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS) {
				goto out;
			} else if (traffic_class_index == 1) {
				rc = str_to_num(content, NUM_TYPE_U32, ele_val,
						&tmp, err_msg, node_path);
				if (rc < 0)
					goto out;
				admin_conf->qbv_conf.maxsdu = (uint32_t)tmp;
			}
		}
	}
out:
	return rc;
}


int parse_gate_paras(xmlNode *node, struct std_qbv_conf *admin_conf,
	char *err_msg, char *node_path)
{
	int rc = EXIT_SUCCESS;
	char *content;
	uint32_t list_index = 0;
	uint32_t list_len = 0;
	xmlNode *tmp_node = node;
	uint64_t tmp;
	char ele_val[MAX_ELEMENT_LENGTH];
	char path[MAX_PATH_LENGTH];

	/* Get admin-control-list-length node */
	tmp_node = get_child_node(node, "admin-control-list-length");
	if (!tmp_node) {
		goto parse_loop;
	}
	rc = xml_read_field(tmp_node, "admin-control-list-length",
			    ele_val, err_msg, node_path);
	if (rc != EXIT_SUCCESS)
		goto out;
	rc = str_to_num("admin-control-list-length", NUM_TYPE_U32, ele_val,
			&tmp, err_msg, node_path);
	if (rc < 0)
		goto out;
	admin_conf->qbv_conf.admin.control_list_length = (uint32_t)tmp;
	list_len = (uint32_t)tmp;
parse_loop:
	for (tmp_node = node->children; tmp_node != NULL;
	     tmp_node = tmp_node->next) {
		if (tmp_node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)tmp_node->name;
		if (strcmp(content, "gate-enabled") == 0) {
			rc = xml_read_field(tmp_node, "gate-enabled",
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;
			if (strcmp(ele_val, "true") == 0) {
				admin_conf->qbv_conf.gate_enabled = TRUE;
			} else if (strcmp(ele_val, "false") == 0) {
				admin_conf->qbv_conf.gate_enabled = FALSE;
				return rc; // don't need to parse other params
			} else {
				prt_err_bool(err_msg, content, node_path);
				rc = EXIT_FAILURE;
				goto out;
			}
		} else if (strcmp(content, "admin-gate-states") == 0) {
			rc = xml_read_field(tmp_node, "admin-gate-states",
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;
			rc = str_to_num(content, NUM_TYPE_U8, ele_val,
					&tmp, err_msg, node_path);
			if (rc < 0)
				goto out;
			admin_conf->qbv_conf.admin.gate_states = (uint8_t) tmp;
		} else if (strcmp(content, "admin-cycle-time") == 0) {
			strcpy(path, node_path);
			strcat(path, "/");
			strcat(path, content);
			rc = get_cycle_time(tmp_node, &admin_conf->qbv_conf.admin.cycle_time,
				err_msg, path);
			if (rc != EXIT_SUCCESS)
				goto out;
		} else if (strcmp(content, "admin-cycle-time-extension") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;
			rc = str_to_num(content, NUM_TYPE_U32, ele_val,
					&tmp, err_msg, node_path);
			if (rc < 0)
				goto out;
			admin_conf->qbv_conf.admin.cycle_time_extension = (uint32_t)tmp;
		} else if (strcmp(content, "admin-base-time") == 0) {
			strcpy(path, node_path);
			strcat(path, "/");
			strcat(path, content);
			rc = qbv_parse_admin_base_time(tmp_node, admin_conf,
				err_msg, path);
			if (rc != EXIT_SUCCESS)
				goto out;
		} else if (strcmp(content, "config-change") == 0) {
			rc = xml_read_field(tmp_node, "config-change",
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			if (strcmp(ele_val, "true") == 0) {
				admin_conf->qbv_conf.config_change = TRUE;
			} else if (strcmp(ele_val, "false") == 0) {
				admin_conf->qbv_conf.config_change = FALSE;
			} else {
				prt_err_bool(err_msg, content, node_path);
				rc = EXIT_FAILURE;
				goto out;
			}
		} else if (strcmp(content, "admin-control-list") == 0) {
			strcpy(path, node_path);
			strcat(path, "/");
			strcat(path, content);
			if (list_index >= list_len)
				continue;
			rc = qbv_parse_admin_control_list(tmp_node, admin_conf,
				list_index, err_msg, path);
			if (rc != EXIT_SUCCESS)
				goto out;
			list_index++;
		}
	}
out:
	return rc;
}

int probe_qbv_cfg(xmlNodePtr xml_node, cJSON *json_ob)
{
	int list_cnt;
	cJSON *admin = NULL, *oper = NULL, *item =  NULL;
	cJSON *list = NULL, *time = NULL;
	cJSON *target = NULL;
	xmlNodePtr time_node;
	xmlNodePtr list_node;
	xmlNodePtr qbv_node;
	xmlNodePtr temp_node;
	char temp[80] = {0};
	uint64_t second = 0;
	uint64_t nanosecond = 0;
	uint64_t temp_ul = 0;
	uint32_t temp_int = 0;
	int i = 0;
	int ret = 0;
	xmlNsPtr ns;

	nc_verb_verbose("%s is called", __func__);
	qbv_node = xmlNewChild(xml_node, NULL, BAD_CAST "gate-parameters",
				     NULL);
	ns = xmlNewNs(qbv_node, BAD_CAST QBV_NS, BAD_CAST QBV_PREFIX);
	xmlSetNs(qbv_node, ns);
	item = cJSON_GetObjectItem(json_ob, "disable");
	if (item) {
		xmlNewTextChild(qbv_node, NULL,
				BAD_CAST "gate-enabled", BAD_CAST "false");
		ret = QBV_DISABLE;
		goto out;
	} else {
		xmlNewTextChild(qbv_node, NULL,
				BAD_CAST "gate-enabled", BAD_CAST "true");
	}
	item = cJSON_GetObjectItem(json_ob, "configpending");
	if (item) {
		ret = CFG_PEND;
		goto out;
	}
	admin = cJSON_GetObjectItem(json_ob, "admin");
	oper = cJSON_GetObjectItem(json_ob, "oper");
	target = admin ? admin : oper;
	if (!target)
		goto out;
	item = cJSON_GetObjectItem(target, "listcount");
	if (item) {
		temp_ul = (uint64_t)(item->valuedouble);
		if (!temp_ul) {
			ret = CFG_PEND;
			goto out;
		}
		sprintf(temp, "%ld", temp_ul);
		xmlNewTextChild(qbv_node, NULL,
				BAD_CAST "admin-control-list-length",
				BAD_CAST temp);
	}
	list_cnt = (int)(temp_ul);

	item = cJSON_GetObjectItem(target, "gatestate");
	if (item) {
		temp_ul = (uint64_t)(item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		xmlNewTextChild(qbv_node, NULL,
				BAD_CAST "admin-gate-states",
				BAD_CAST temp);
	}
	time = cJSON_GetObjectItem(target, "cycletime");
	if (time) {
		temp_node = xmlNewChild(qbv_node, NULL,
					BAD_CAST "admin-cycle-time",
					NULL);
		temp_ul = (uint64_t)(time->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		xmlNewTextChild(temp_node, NULL, BAD_CAST "numerator",
				BAD_CAST temp);
		xmlNewTextChild(temp_node, NULL,
				BAD_CAST "denominator",
				BAD_CAST "1000000000");
	}
	item = cJSON_GetObjectItem(target, "cycletimeext");
	if (item) {
		temp_ul = (uint64_t)(item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		xmlNewTextChild(qbv_node, NULL,
				BAD_CAST "admin-cycle-time-extension",
				BAD_CAST temp);
	}
	for (i = 0; i < list_cnt; i++) {
		list = get_list_item(target, "list", i);
		if (list == NULL)
			goto out;

		list_node = xmlNewChild(qbv_node, NULL,
					BAD_CAST "admin-control-list",
					NULL);

		item = cJSON_GetObjectItem(list, "entryid");
		if (item) {
			temp_int = (uint32_t)(item->valuedouble);
			sprintf(temp, "%d", temp_int);
			xmlNewTextChild(list_node, NULL,
					BAD_CAST "index",
					BAD_CAST temp);
		}
		temp_node = xmlNewChild(list_node, NULL,
					BAD_CAST "operation-name",
					BAD_CAST "sched:set-gate-states");
		temp_node = xmlNewChild(list_node, NULL,
					BAD_CAST "sgs-params",
					NULL);
		item = cJSON_GetObjectItem(list, "gate");
		if (item) {
			temp_int = (uint32_t)(item->valuedouble);
			sprintf(temp, "%d", temp_int);
			xmlNewTextChild(temp_node, NULL,
					BAD_CAST "gate-states-value",
					BAD_CAST temp);
		}
		item = cJSON_GetObjectItem(list, "timeperiod");
		if (item) {
			temp_int = (uint32_t)(item->valuedouble);
			sprintf(temp, "%d", temp_int);
			xmlNewTextChild(temp_node, NULL,
					BAD_CAST "time-interval-value",
					BAD_CAST temp);
		}
	}
	item = cJSON_GetObjectItem(target, "basetime");
	if (item) {
		second = ((uint64_t)item->valuedouble/1000000000);
		nanosecond = ((uint64_t)item->valuedouble%1000000000);
		time_node = xmlNewChild(qbv_node, NULL,
					BAD_CAST "admin-base-time",
					NULL);
		sprintf(temp, "%ld", second);
		xmlNewTextChild(time_node, NULL, BAD_CAST "seconds",
				BAD_CAST temp);
		sprintf(temp, "%ld", nanosecond);
		xmlNewTextChild(time_node, NULL,
				BAD_CAST "fractional-seconds",
				BAD_CAST temp);
	}
out:
	return ret;
}

int probe_qbv_st(xmlNodePtr xml_node, cJSON *json_ob)
{
	int list_cnt;
	cJSON *oper = NULL, *item =  NULL;
	cJSON *list = NULL, *time = NULL;
	xmlNodePtr oper_node;
	xmlNodePtr time_node;
	xmlNodePtr list_node;
	xmlNodePtr temp_node;
	xmlNodePtr qbv_node;
	char temp[80] = {0};
	uint64_t second = 0;
	uint64_t nanosecond = 0;
	uint64_t temp_ul = 0;
	uint32_t temp_int = 0;
	int i = 0;
	int ret = 0;
	xmlNsPtr ns;

	nc_verb_verbose("%s is called", __func__);
	item = cJSON_GetObjectItem(json_ob, "disable");
	if (item)
		goto out;

	qbv_node = xmlNewChild(xml_node, NULL, BAD_CAST "gate-parameters",
				     NULL);
	ns = xmlNewNs(qbv_node, BAD_CAST QBV_NS, BAD_CAST QBV_PREFIX);
	xmlSetNs(qbv_node, ns);
	item = cJSON_GetObjectItem(json_ob, "configchangetime");
	if (item) {
		second = ((uint64_t)item->valuedouble/1000000000);
		nanosecond = ((uint64_t)item->valuedouble%1000000000);
		time_node = xmlNewChild(qbv_node, NULL,
					BAD_CAST "config-change-time", NULL);
		sprintf(temp, "%ld", second);
		if (time_node) {
			xmlNewTextChild(time_node, NULL,
					BAD_CAST "seconds", BAD_CAST temp);
			sprintf(temp, "%ld", nanosecond);
			xmlNewTextChild(time_node, NULL,
					BAD_CAST "fractional-seconds",
					BAD_CAST temp);
		}
	}
	item = cJSON_GetObjectItem(json_ob, "currenttime");
	if (item) {
		second = ((uint64_t)item->valuedouble/1000000000);
		nanosecond = ((uint64_t)item->valuedouble%1000000000);
		time_node = xmlNewChild(qbv_node, NULL,
					BAD_CAST "current-time", NULL);
		sprintf(temp, "%ld", second);
		xmlNewTextChild(time_node, NULL,
				BAD_CAST "seconds", BAD_CAST temp);
		sprintf(temp, "%ld", nanosecond);
		xmlNewTextChild(time_node, NULL,
				BAD_CAST "fractional-seconds", BAD_CAST temp);
	}
	item = cJSON_GetObjectItem(json_ob, "configpending");
	if (item) {
		xmlNewTextChild(qbv_node, NULL,
				BAD_CAST "config-pending", BAD_CAST "true");
		ret = CFG_PEND;
	}

	item = cJSON_GetObjectItem(json_ob, "listmax");
	if (item) {
		second = (uint64_t)(item->valuedouble);
		sprintf(temp, "%ld", second);
		xmlNewTextChild(qbv_node, NULL,
				BAD_CAST "supported-list-max", BAD_CAST temp);
	}

	oper = cJSON_GetObjectItem(json_ob, "oper");
	if (!oper)
		goto out;
	oper_node = xmlNewChild(qbv_node, NULL, BAD_CAST "oper", NULL);
	item = cJSON_GetObjectItem(oper, "gatestate");
	if (item) {
		temp_ul = (uint64_t)(item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		xmlNewTextChild(oper_node, NULL,
				BAD_CAST "oper-gate-states",
				BAD_CAST temp);
	}
	item = cJSON_GetObjectItem(oper, "listcount");
	if (item) {
		temp_ul = (uint64_t)(item->valuedouble);
		if (!temp_ul)
			ret = CFG_PEND;
		sprintf(temp, "%ld", temp_ul);
		xmlNewTextChild(oper_node, NULL,
				BAD_CAST "oper-control-list-length",
				BAD_CAST temp);
	}
	list_cnt = (int)(temp_ul);
	time = cJSON_GetObjectItem(oper, "cycletime");
	if (time) {
		temp_node = xmlNewChild(oper_node, NULL,
					BAD_CAST "oper-cycle-time",
					NULL);
		temp_ul = (uint64_t)(time->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		xmlNewTextChild(temp_node, NULL, BAD_CAST "numerator",
				BAD_CAST temp);
		xmlNewTextChild(temp_node, NULL,
				BAD_CAST "denominator",
				BAD_CAST "1000000000");
	}
	item = cJSON_GetObjectItem(oper, "cycletimeext");
	if (item) {
		temp_ul = (uint64_t)(item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		xmlNewTextChild(oper_node, NULL,
				BAD_CAST "oper-cycle-time-extension",
				BAD_CAST temp);
	}
	for (i = 0; i < list_cnt; i++) {
		list = get_list_item(oper, "list", i);
		if (list == NULL )
			goto out;

		list_node = xmlNewChild(oper_node, NULL,
					BAD_CAST "oper-control-list",
					NULL);

		item = cJSON_GetObjectItem(list, "entryid");
		if (item) {
			temp_int = (uint32_t)(item->valuedouble);
			sprintf(temp, "%d", temp_int);
			xmlNewTextChild(list_node, NULL,
					BAD_CAST "index",
					BAD_CAST temp);
		}
		temp_node = xmlNewChild(list_node, NULL,
					BAD_CAST "operation-name",
					BAD_CAST "sched:set-gate-states");
		temp_node = xmlNewChild(list_node, NULL,
					BAD_CAST "sgs-params",
					NULL);
		item = cJSON_GetObjectItem(list, "gate");
		if (item) {
			temp_int = (uint32_t)(item->valuedouble);
			sprintf(temp, "%d", temp_int);
			xmlNewTextChild(temp_node, NULL,
					BAD_CAST "gate-states-value",
					BAD_CAST temp);
		}
		item = cJSON_GetObjectItem(list, "timeperiod");
		if (item) {
			temp_int = (uint32_t)(item->valuedouble);
			sprintf(temp, "%d", temp_int);
			xmlNewTextChild(temp_node, NULL,
					BAD_CAST "time-interval-value",
					BAD_CAST temp);
		}
	}
	item = cJSON_GetObjectItem(oper, "basetime");
	if (item) {
		second = ((uint64_t)item->valuedouble/1000000000);
		nanosecond = ((uint64_t)item->valuedouble%1000000000);
		time_node = xmlNewChild(xml_node, NULL,
					BAD_CAST "oper-base-time",
					NULL);
		sprintf(temp, "%ld", second);
		xmlNewTextChild(time_node, NULL, BAD_CAST "seconds",
				BAD_CAST temp);
		sprintf(temp, "%ld", nanosecond);
		xmlNewTextChild(time_node, NULL,
				BAD_CAST "fractional-seconds",
				BAD_CAST temp);
	}
out:
	return ret;
}

int get_qbv_info(char *port, xmlNodePtr node, int mode)
{
	FILE *fp;
	int rc = EXIT_SUCCESS;
	int len = 0;
	cJSON *json;
	struct tsn_qbv_status qbvstaus;
	struct tsn_qbv_conf qbvconf;
	char *json_data;
	int retry = 0;
	xmlNodePtr tmp_node;

	nc_verb_verbose("%s is called", __func__);
	/* Add interface node */
	if (port == NULL)
		return EXIT_FAILURE;
RETRY:
	init_tsn_socket();
	if (retry)
		rc = tsn_qos_port_qbv_get(port, &qbvconf);
	else
		rc = tsn_qos_port_qbv_status_get(port, &qbvstaus);
	close_tsn_socket();
	if (rc < 0)
		goto out;

	fp = fopen(TSNTOOL_PORT_ST_FILE, "r");
	if (fp) {
		nc_verb_verbose("open '%s' ok", TSNTOOL_PORT_ST_FILE);
		fseek(fp, 0, SEEK_END);
		len = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		json_data = (char *)malloc(len+1);
		if (json_data) {
			fread(json_data, 1, len, fp);
			json = cJSON_Parse(json_data);
			if (json) {
				if (mode == 1) {
					tmp_node = xmlNewNode(NULL,
							      BAD_CAST "tmp");
					rc = probe_qbv_cfg(tmp_node, json);
					if (rc == CFG_PEND) {
						unlink_child(tmp_node);
						cJSON_Delete(json);
						retry = 1;
						goto RETRY;
					}
					xmlAddChildList(node,
							tmp_node->children);
				} else {
					probe_qbv_st(node, json);
				}
				cJSON_Delete(json);
			} else {
				nc_verb_verbose("qbv json parse error");
			}
			free(json_data);
		} else {
			nc_verb_verbose("malloc error");
		}
		fclose(fp);
	} else {
		nc_verb_verbose("open '%s' error", TSNTOOL_PORT_ST_FILE);
	}
out:
	return rc;
}

int parse_qbv_node(xmlNode *node, struct std_qbv_conf *admin_conf,
			  char *err_msg, char *node_path)
{
	int rc = EXIT_SUCCESS;
	char *content;
	char path[MAX_PATH_LENGTH];
	xmlNode *tmp_node = node;

	nc_verb_verbose("%s is called", __func__);

	for (tmp_node = node->children; tmp_node != NULL;
	     tmp_node = tmp_node->next) {
		if (tmp_node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)tmp_node->name;
		if (strcmp(content, "max-sdu-table") == 0) {
			strcpy(path, node_path);
			strcat(path, "/");
			strcat(path, content);
			rc = parse_max_sdu_table(tmp_node, admin_conf,
						 err_msg, path);
			if (rc != EXIT_SUCCESS)
				goto out;
		} else if (strcmp(content, "gate-parameters") == 0) {
			strcpy(path, node_path);
			strcat(path, "/");
			strcat(path, content);
			rc = parse_gate_paras(tmp_node, admin_conf,
					      err_msg, path);
			if (rc != EXIT_SUCCESS)
				goto out;
		}
	}
out:
	return rc;
}
