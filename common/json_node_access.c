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
#include <sys/file.h>
#include <libxml/tree.h>
#include <libnetconf_xml.h>
#include <pthread.h>
#include <semaphore.h>
#include <cjson/cJSON.h>
#include <errno.h>
#include <time.h>
#include "platform.h"

cJSON *get_list_item(const cJSON *object, const char *name, int index)
{
	int cnt = 0;
	cJSON *ele;

	if ((object == NULL) || (name == NULL))
		return NULL;

	for (ele = object->child; ele != NULL; ele = ele->next) {
		if (!strcmp(name, ele->string)) {
			if (index == cnt)
				break;
			cnt++;
		}
	}

	if ((ele == NULL) || (ele->string == NULL))
		return NULL;

	return ele;
}

void create_op_record(char *ifname, char *path, int tsn, int parameter)
{
	FILE *fp;
	char *buf;
	cJSON *json = NULL;
	cJSON *item = NULL;
	cJSON *op_node = NULL;
	time_t op_time;

	if (!ifname || !path) {
		nc_verb_verbose("Invalid ifname or path");
		return;
	}
	errno = 0;
	fp = fopen(path, "w");
	if (!fp) {
		nc_verb_verbose("open '%s' failed: %s", path, strerror(errno));
		return;
	}

	json = cJSON_CreateObject();
	if (!json) {
		nc_verb_verbose("create cJSON object failed!");
		fclose(fp);
		return;
	}
	op_node = cJSON_CreateObject();
	if (!json) {
		nc_verb_verbose("create cJSON object failed!");
		fclose(fp);
		return;
	}

	time(&op_time);
	item = cJSON_CreateNumber((double)op_time);
	cJSON_AddItemToObject(json, "time", item);

	item = cJSON_CreateString(ifname);
	cJSON_AddItemToObject(op_node, "port", item);
	item = cJSON_CreateNumber((double)tsn);
	cJSON_AddItemToObject(op_node, "cmd-type", item);
	item = cJSON_CreateNumber((double)parameter);
	cJSON_AddItemToObject(op_node, "parameter", item);

	cJSON_AddItemToObject(json, "operation", op_node);
	buf = cJSON_Print(json);
	fwrite(buf, strlen(buf), 1, fp);
	free(buf);
	cJSON_Delete(json);
	fclose(fp);
}
/* Need cJSON_Delete() to free json memory */
cJSON *open_json_safe(char *file, char *mode)
{
	FILE *fp = NULL;
	int len = 0;
	char *json_data;
	cJSON *json;

	nc_verb_verbose("commen json open");
	errno = 0;
	fp = fopen(file, mode);
	if (!fp) {
		nc_verb_verbose("open '%s' failed: '%s'",
				file, strerror(errno));
		return NULL;
	}
	errno = 0;
	if (flock(fp->_fileno, LOCK_EX) == -1) {
		nc_verb_verbose("lock '%s' failed: '%s'",
				file, strerror(errno));
		fclose(fp);
		return NULL;
	}
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	json_data = (char *)malloc(len + 1);
	if (json_data) {
		fread(json_data, 1, len, fp);
		json = cJSON_Parse(json_data);
		if (!json) {
			nc_verb_verbose("commont json parse error");
			free(json_data);
			fclose(fp);
			flock(fp->_fileno, LOCK_UN);
			return NULL;
		}
	} else {
		nc_verb_verbose("malloc error");
		fclose(fp);
		flock(fp->_fileno, LOCK_UN);
		return NULL;
	}
	fclose(fp);
	flock(fp->_fileno, LOCK_UN);
	free(json_data);
	return json;
}

int get_opr_info(char *file, char *port_name, int *type, int *parameter)
{
	cJSON *json;
	cJSON *oper;
	cJSON *cmd_type;
	cJSON *port;
	cJSON *param;

	json = open_json_safe(file, "r");
	if (!json) {
		nc_verb_verbose("open '%s' failed!", file);
		return EXIT_FAILURE;
	}
	oper = cJSON_GetObjectItem(json, "operation");
	if (!oper) {
		nc_verb_verbose("get tsn's operation item failed!");
		cJSON_Delete(json);
		return EXIT_FAILURE;
	}
	cmd_type = cJSON_GetObjectItem(oper, "cmd-type");
	if (!cmd_type) {
		nc_verb_verbose("get tsn's cmd-type item failed!");
		cJSON_Delete(json);
		return EXIT_FAILURE;
	}
	port = cJSON_GetObjectItem(oper, "port");
	if (!port) {
		nc_verb_verbose("get port item failed!");
		cJSON_Delete(json);
		return EXIT_FAILURE;
	}
	param = cJSON_GetObjectItem(oper, "parameter");
	if (!param) {
		nc_verb_verbose("get parameter item failed!");
		cJSON_Delete(json);
		return EXIT_FAILURE;
	}
	*type = (int)cmd_type->valuedouble;
	sprintf(port_name, port->valuestring);
	*parameter = (int)param->valuedouble;
	//nc_verb_verbose("parameter is :%f", param->valuedouble);
	//nc_verb_verbose("port is :%s", port->valuestring);
	//nc_verb_verbose("type is :%f", cmd_type->valuedouble);
	return EXIT_SUCCESS;
}

int is_netconf_op(char *tsn_opr, char *netconf_opr)
{
	cJSON *tsn;
	cJSON *tsn_time;
	cJSON *tsn_op;
	cJSON *netconf;
	cJSON *netconf_time;
	cJSON *netconf_op;
	int rc = 0;

	tsn = open_json_safe(tsn_opr, "r");
	if (!tsn) {
		nc_verb_verbose("open '%s' failed!", tsn_opr);
		return 0;
	}
	tsn_op = cJSON_GetObjectItem(tsn, "operation");
	if (!tsn_op) {
		nc_verb_verbose("get tsn's operation item failed!");
		cJSON_Delete(tsn);
		return 0;
	}
	netconf = open_json_safe(netconf_opr, "r");
	if (!netconf) {
		nc_verb_verbose("open '%s' failed!", netconf_opr);
		return 0;
	}
	netconf_op = cJSON_GetObjectItem(netconf, "operation");
	if (!netconf_op) {
		nc_verb_verbose("get netconf's operation item failed!");
		cJSON_Delete(tsn);
		cJSON_Delete(netconf);
		return 0;
	}

	if (cJSON_Compare(tsn_op, netconf_op, 1) == 0)
		return 0;

	tsn_time = cJSON_GetObjectItem(tsn, "time");
	if (!tsn_time) {
		cJSON_Delete(tsn);
		cJSON_Delete(netconf);
		nc_verb_verbose("get tsn's time item failed!");
		return 0;
	}
	netconf_time = cJSON_GetObjectItem(netconf, "time");
	if (!netconf_time) {
		cJSON_Delete(tsn);
		cJSON_Delete(netconf);
		nc_verb_verbose("get netconf's time item failed!");
		return 0;
	}

	if (tsn_time->valuedouble - netconf_time->valuedouble < 3)
		rc =  1;
	cJSON_Delete(tsn);
	cJSON_Delete(netconf);
	return rc;
}
