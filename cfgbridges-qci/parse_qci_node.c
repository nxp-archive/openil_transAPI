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
#include "bridges.h"
#include "parse_qci_node.h"
#include "xml_node_access.h"
#include "json_node_access.h"

void init_qci_memory(struct std_qci_conf *qci_conf)
{
	memset(qci_conf, 0, sizeof(struct std_qci_conf));
}

struct std_qci_psfp_sfi_table *creat_new_sfi_instance(void)
{
	struct std_qci_psfp_sfi_table *sfi_table_ptr;
	struct std_qci_psfp_sfi *sfi_ptr;

	nc_verb_verbose("%s is called", __func__);
	sfi_table_ptr = calloc(1, sizeof(struct std_qci_psfp_sfi_table));
	if (!sfi_table_ptr)
		return sfi_table_ptr;
	sfi_ptr = calloc(1, sizeof(struct std_qci_psfp_sfi));
	if (!sfi_ptr) {
		free(sfi_table_ptr);
		return NULL;
	}
	sfi_table_ptr->sfi_ptr = sfi_ptr;
	sfi_table_ptr->next = NULL;
	sfi_ptr->sficonf.stream_handle_spec = -1;
	sfi_ptr->sficonf.priority_spec = -1;
	sfi_ptr->sficonf.stream_filter.flow_meter_instance_id = -1;
	//nc_verb_verbose("%p is calloced", sfi_table_ptr);
	//nc_verb_verbose("%p is calloced", sfi_ptr);
	return sfi_table_ptr;
}
void free_sfi_memory(struct std_qci_psfp_sfi_table *sfi_table)
{
	struct std_qci_psfp_sfi_table *tmp_table = sfi_table;
	struct std_qci_psfp_sfi_table *next_table;

	nc_verb_verbose("%s is called", __func__);
	while (tmp_table) {
		next_table = tmp_table->next;
		//nc_verb_verbose("%p is freed", tmp_table);
		//nc_verb_verbose("%p is freed", tmp_table->sfi_ptr);
		if (tmp_table->sfi_ptr)
			free(tmp_table->sfi_ptr);
		free(tmp_table);
		tmp_table = next_table;
	}
}

struct std_qci_psfp_sgi_table *creat_new_sgi_instance(void)
{
	struct std_qci_psfp_sgi_table *sgi_table_ptr;
	struct std_qci_psfp_sgi *sgi_ptr;

	nc_verb_verbose("%s is called", __func__);
	sgi_table_ptr = calloc(1, sizeof(struct std_qci_psfp_sgi_table));
	if (!sgi_table_ptr)
		return sgi_table_ptr;
	sgi_ptr = calloc(1, sizeof(struct std_qci_psfp_sgi));
	if (!sgi_ptr) {
		free(sgi_table_ptr);
		return NULL;
	}
	sgi_ptr->sgiconf.admin.gcl = malloc(MAX_ENTRY_SIZE);
	if (!sgi_ptr->sgiconf.admin.gcl) {
		free(sgi_table_ptr);
		free(sgi_ptr);
		return NULL;
	}
	sgi_table_ptr->sgi_ptr = sgi_ptr;
	sgi_table_ptr->next = NULL;
	sgi_ptr->sgiconf.admin.init_ipv = -1;
	//nc_verb_verbose("%p is calloced", sgi_table_ptr);
	//nc_verb_verbose("%p is calloced", sgi_ptr);
	//nc_verb_verbose("%p is calloced", sgi_ptr->sgiconf.admin.gcl);
	return sgi_table_ptr;
}
void free_sgi_memory(struct std_qci_psfp_sgi_table *sgi_table)
{
	struct std_qci_psfp_sgi_table *tmp_table = sgi_table;
	struct std_qci_psfp_sgi_table *next_table;

	nc_verb_verbose("%s is called", __func__);
	while (tmp_table) {
		next_table = tmp_table->next;
		//nc_verb_verbose("%p is freed", tmp_table);
		//nc_verb_verbose("%p is freed", tmp_table->sgi_ptr);
		//nc_verb_verbose("%p is freed",
		//		  tmp_table->sgi_ptr->sgiconf.admin.gcl);
		if (tmp_table->sgi_ptr) {
			if (tmp_table->sgi_ptr->sgiconf.admin.gcl)
				free(tmp_table->sgi_ptr->sgiconf.admin.gcl);
			free(tmp_table->sgi_ptr);
		}
		free(tmp_table);
		tmp_table = next_table;
	}
}

struct std_qci_psfp_fmi_table *creat_new_fmi_instance(void)
{
	struct std_qci_psfp_fmi_table *fmi_table_ptr;
	struct std_qci_psfp_fmi *fmi_ptr;

	nc_verb_verbose("%s is called", __func__);
	fmi_table_ptr = calloc(1, sizeof(struct std_qci_psfp_fmi_table));
	if (!fmi_table_ptr)
		return fmi_table_ptr;
	fmi_ptr = calloc(1, sizeof(struct std_qci_psfp_fmi));
	if (!fmi_ptr)
		free(fmi_table_ptr);

	fmi_table_ptr->fmi_ptr = fmi_ptr;
	fmi_table_ptr->next = NULL;
	//nc_verb_verbose("%p is calloced", fmi_table_ptr);
	//nc_verb_verbose("%p is calloced", fmi_ptr);
	return fmi_table_ptr;
}
void free_fmi_memory(struct std_qci_psfp_fmi_table *fmi_table)
{
	struct std_qci_psfp_fmi_table *tmp_table = fmi_table;
	struct std_qci_psfp_fmi_table *next_table;

	nc_verb_verbose("%s is called", __func__);

	while (tmp_table) {
		next_table = tmp_table->next;
		//nc_verb_verbose("%p is freed", tmp_table);
		//nc_verb_verbose("%p is freed", tmp_table->fmi_ptr);
		if (tmp_table->fmi_ptr)
			free(tmp_table->fmi_ptr);
		free(tmp_table);
		tmp_table = next_table;
	}
}
void free_qci_memory(struct std_qci_conf *qci_conf)
{
	free_sfi_memory(qci_conf->sfi_table);
	qci_conf->sfi_table = NULL;
	free_sgi_memory(qci_conf->sgi_table);
	qci_conf->sgi_table = NULL;
	free_fmi_memory(qci_conf->fmi_table);
	qci_conf->fmi_table = NULL;
}

int parse_filter_spec_list(xmlNode *node, struct std_qci_psfp_sfi *cur_sfi,
	char *err_msg, char *node_path)
{
	int rc = EXIT_SUCCESS;
	char *content;
	uint64_t tmp;
	xmlNode *tmp_node;
	char ele_val[MAX_ELEMENT_LENGTH];

	nc_verb_verbose("%s is called", __func__);

	for (tmp_node = node->children; tmp_node != NULL;
	     tmp_node = tmp_node->next) {
		if (node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)tmp_node->name;
		if (strcmp(content, "maximum-sdu-size") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			rc = str_to_num(content, NUM_TYPE_U32, ele_val, &tmp,
					err_msg, node_path);
			if (rc < 0)
				goto out;
			cur_sfi->sficonf.stream_filter.maximum_sdu_size = (int32_t)tmp;
		} else if (strcmp(content, "stream-blocked-due-to-oversize-frame-enabled") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			if (strcmp(ele_val, "true") == 0) {
				cur_sfi->sficonf.block_oversize_enable = TRUE;
			} else if (strcmp(ele_val, "false") == 0) {
				cur_sfi->sficonf.block_oversize_enable = FALSE;
			} else {
				prt_err_bool(err_msg, content, node_path);
				rc = EXIT_FAILURE;
				goto out;
			}
		} else if (strcmp(content, "flow-meter-ref") == 0) {
			rc = xml_read_field(tmp_node, "flow-meter-ref",
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			rc = str_to_num(content, NUM_TYPE_U32, ele_val, &tmp,
					err_msg, node_path);
			if (rc < 0)
				goto out;
			cur_sfi->sficonf.stream_filter.flow_meter_instance_id = (int32_t)tmp;
		} else if (strcmp(content, "index") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS) {
				goto out;
			} else {
				str_del_last_key(node_path);
				strcat(node_path, "(");
				strcat(node_path, ele_val);
				strcat(node_path, ")");
			}
		}
	}
out:
	return rc;
}

int parse_stream_filter_table(xmlNode *node,
	struct std_qci_psfp_sfi_table *sfi_table,
	char *err_msg, char *node_path)
{
	int rc = EXIT_SUCCESS;
	char *content;
	uint64_t tmp;
	xmlNode *tmp_node;
	char ele_val[MAX_ELEMENT_LENGTH];
	char path[MAX_PATH_LENGTH];
	int stream_handle_spec = 0;
	struct std_qci_psfp_sfi *cur_sfi = sfi_table->sfi_ptr;

	nc_verb_verbose("%s is called", __func__);
	tmp_node = node;
	for (tmp_node = node->children; tmp_node != NULL;
	     tmp_node = tmp_node->next) {
		if (tmp_node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)tmp_node->name;
		if (strcmp(content, "stream-filter-instance-id") == 0) {
			rc = xml_read_field(tmp_node,
					    "stream-filter-instance-id",
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			str_del_last_key(node_path);
			strcat(node_path, "(");
			strcat(node_path, ele_val);
			strcat(node_path, ")");
			rc = str_to_num(content, NUM_TYPE_U8, ele_val, &tmp,
					err_msg, node_path);
			if (rc < 0)
				goto out;
			cur_sfi->stream_filter_instance_id = (uint8_t)tmp;
		} else if (strcmp(content, "stream-filter-enabled") == 0) {
			rc = xml_read_field(tmp_node, content, ele_val,
					    err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			if (strcmp(ele_val, "true") == 0) {
				sfi_table->sfi_ptr->enable = TRUE;
			} else if (strcmp(ele_val, "false") == 0) {
				sfi_table->sfi_ptr->enable = FALSE;
			} else {
				prt_err_bool(err_msg, content, node_path);
				rc = EXIT_SUCCESS;
				goto out;
			}
		} else if (strcmp(content, "wildcard") == 0) {
			stream_handle_spec++;
			cur_sfi->sficonf.stream_handle_spec = -1;
		} else if (strcmp(content, "stream-handle") == 0) {
			stream_handle_spec++;
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			rc = str_to_num(content, NUM_TYPE_U32, ele_val, &tmp,
					err_msg, node_path);
			if (rc < 0)
				goto out;
			cur_sfi->sficonf.stream_handle_spec = (int32_t)(tmp);

		} else if (strcmp(content, "priority-spec") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			if (strcmp(ele_val, "zero") == 0) {
				cur_sfi->sficonf.priority_spec = 0;
			} else if (strcmp(ele_val, "one") == 0) {
				cur_sfi->sficonf.priority_spec = 1;
			} else if (strcmp(ele_val, "two") == 0) {
				cur_sfi->sficonf.priority_spec = 2;
			} else if (strcmp(ele_val, "three") == 0) {
				cur_sfi->sficonf.priority_spec = 3;
			} else if (strcmp(ele_val, "four") == 0) {
				cur_sfi->sficonf.priority_spec = 4;
			} else if (strcmp(ele_val, "five") == 0) {
				cur_sfi->sficonf.priority_spec = 5;
			} else if (strcmp(ele_val, "six") == 0) {
				cur_sfi->sficonf.priority_spec = 6;
			} else if (strcmp(ele_val, "seven") == 0) {
				cur_sfi->sficonf.priority_spec = 7;
			} else if (strcmp(ele_val, "wildcard") == 0) {
				cur_sfi->sficonf.priority_spec = -1;
			} else {
				sprintf(err_msg,
					"'%s' in '%s' is out of range!",
					content, node_path);
				rc = EXIT_FAILURE;
				goto out;
			}
		} else if (strcmp(content, "stream-gate-ref") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			rc = str_to_num(content, NUM_TYPE_U32, ele_val, &tmp,
					err_msg, node_path);
			if (rc < 0)
				goto out;
			cur_sfi->sficonf.stream_gate_instance_id = (uint32_t)(tmp);
		} else if (strcmp(content, "filter-specification-list") == 0) {
			strcpy(path, node_path);
			strcat(path, "/");
			strcat(path, content);
			rc = parse_filter_spec_list(tmp_node, cur_sfi,
						    err_msg, path);
			if (rc != EXIT_SUCCESS)
				goto out;
		}
	}
	if (stream_handle_spec > 1) {
		rc = EXIT_FAILURE;
		sprintf(err_msg,
			"'%s' in '%s' is a choice node, please use one case!",
			content, node_path);
	}
out:
	return rc;
}

int parse_stream_filters(xmlNode *node, struct std_qci_conf *qci_conf,
	char *err_msg, char *node_path)
{
	int rc = EXIT_SUCCESS;
	char *content;
	xmlNode *tmp_node;
	char path[MAX_PATH_LENGTH];
	struct std_qci_psfp_sfi_table *cur_sfi_table_ptr = NULL;

	nc_verb_verbose("%s is called", __func__);

	tmp_node = node;
	for (tmp_node = node->children; tmp_node != NULL;
	     tmp_node = tmp_node->next) {
		if (tmp_node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)tmp_node->name;
		if (strcmp(content, "stream-filter-instance-table") != 0)
			continue;
		nc_verb_verbose("find sfi table conf");
		if (qci_conf->sfi_table == NULL) {
			qci_conf->sfi_table = creat_new_sfi_instance();
			cur_sfi_table_ptr = qci_conf->sfi_table;
		} else {
			cur_sfi_table_ptr->next = creat_new_sfi_instance();
			cur_sfi_table_ptr = cur_sfi_table_ptr->next;
		}
		if (cur_sfi_table_ptr == NULL) {
			rc = EXIT_FAILURE;
			sprintf(err_msg, "allocate memory for '%s' failure!",
				content);
			goto out;
		}
		strcpy(path, node_path);
		strcat(path, "/");
		strcat(path, content);
		rc = parse_stream_filter_table(tmp_node,
					       cur_sfi_table_ptr,
					       err_msg, path);
		if (rc != EXIT_SUCCESS) {
			nc_verb_verbose("parse filter table err");
			goto out;
		}
	}
out:
	return rc;
}

int stream_filters_handle(char *portname, xmlNode *node,
	   char *err_msg, char *node_path)
{
	int rc = EXIT_SUCCESS;
	struct std_qci_conf qci_conf;
	struct std_qci_psfp_sfi_table *table = NULL;

	nc_verb_verbose("%s is called", __func__);
	/* Init qci configuration data */
	init_qci_memory(&qci_conf);

	rc = parse_stream_filters(node, &qci_conf, err_msg, node_path);
	if (rc != EXIT_SUCCESS)
		goto out;

	table = qci_conf.sfi_table;
	while (table != NULL) {
		/* set new flow meters configuration */
		rc = tsn_qci_psfp_sfi_set(portname,
					  table->sfi_ptr->stream_filter_instance_id,
					  table->sfi_ptr->enable,
					  &(table->sfi_ptr->sficonf));
		if (rc != EXIT_SUCCESS) {
			sprintf(err_msg,
				"failed to set stream identification, %s!",
				strerror(-rc));
			goto out;
		}
		if (table->next == NULL)
			break;
		table = table->next;
	}
out:
	free_qci_memory(&qci_conf);
	return rc;
}

int parse_parameters(xmlNode *node, struct tsn_qci_psfp_sgi_conf *sgi_conf,
	int list_index, char *err_msg, char *node_path)
{
	int rc = EXIT_SUCCESS;
	char *content;
	uint64_t tmp;
	char ele_val[MAX_ELEMENT_LENGTH];
	struct tsn_qci_psfp_gcl *entry;

	nc_verb_verbose("%s is called", __func__);
	entry = sgi_conf->admin.gcl;

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)node->name;
		if (strcmp(content, "gate-state-value") == 0) {
			rc = xml_read_field(node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			if (strcmp(ele_val, "open") == 0) {
				(entry + list_index)->gate_state = TRUE;
			} else if (strcmp(ele_val, "closed") == 0) {
				(entry + list_index)->gate_state = FALSE;
			} else {
				rc = EXIT_FAILURE;
				sprintf(err_msg,
					"unknown '%s' in '%s''!",
					content, node_path);
				goto out;
			}
		} else if (strcmp(content, "ipv-value") == 0) {
			rc = xml_read_field(node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			if (strcmp(ele_val, "zero") == 0) {
				(entry + list_index)->ipv = 0;
			} else if (strcmp(ele_val, "one") == 0) {
				(entry + list_index)->ipv = 1;
			} else if (strcmp(ele_val, "two") == 0) {
				(entry + list_index)->ipv = 2;
			} else if (strcmp(ele_val, "three") == 0) {
				(entry + list_index)->ipv = 3;
			} else if (strcmp(ele_val, "four") == 0) {
				(entry + list_index)->ipv = 4;
			} else if (strcmp(ele_val, "five") == 0) {
				(entry + list_index)->ipv = 5;
			} else if (strcmp(ele_val, "six") == 0) {
				(entry + list_index)->ipv = 6;
			} else if (strcmp(ele_val, "seven") == 0) {
				(entry + list_index)->ipv = 7;
			} else if (strcmp(ele_val, "wildcard") == 0) {
				(entry + list_index)->ipv = -1;
			} else {
				sprintf(err_msg,
					"unknown '%s' in '%s'!",
					content, node_path);
				rc = EXIT_FAILURE;
				goto out;
			}
		} else if (strcmp(content, "time-interval-value") == 0) {
			rc = xml_read_field(node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			rc = str_to_num(content, NUM_TYPE_U32, ele_val, &tmp,
					err_msg, node_path);
			if (rc < 0)
				goto out;
			(entry + list_index)->time_interval = (uint32_t) tmp;
		} else if (strcmp(content, "interval-octet-max") == 0) {
			rc = xml_read_field(node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			rc = str_to_num(content, NUM_TYPE_U32, ele_val, &tmp,
					err_msg, node_path);
			if (rc < 0)
				goto out;
			(entry + list_index)->octet_max = (uint32_t) tmp;
		}
	}
out:
	return rc;
}

int parse_admin_sgl(xmlNode *node, struct tsn_qci_psfp_sgi_conf *sgi_conf,
	uint32_t list_index, char *err_msg,
	char *node_path)
{
	int rc = EXIT_SUCCESS;
	char *content;
	uint64_t tmp;
	xmlNode *tmp_node;
	char ele_val[MAX_ELEMENT_LENGTH];
	char path[MAX_PATH_LENGTH];

	nc_verb_verbose("%s is called", __func__);

	tmp_node = node;
	for (tmp_node = node->children; tmp_node != NULL;
	     tmp_node = tmp_node->next) {
		if (tmp_node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)tmp_node->name;
		if (strcmp(content, "index") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			str_del_last_key(node_path);
			strcat(node_path, "(");
			strcat(node_path, ele_val);
			strcat(node_path, ")");
			rc = str_to_num(content, NUM_TYPE_U32, ele_val, &tmp,
					err_msg, node_path);
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

			if (strstr(ele_val, "set-gate-and-ipv") == NULL) {
				sprintf(err_msg,
					"'%s' must be 'psfp:set-gate-and-ipv'",
					content);
				rc = EXIT_FAILURE;
				goto out;
			}
		} else if (strcmp(content, "parameters") == 0) {
			strcpy(path, node_path);
			strcat(path, "/");
			strcat(path, content);
			rc = parse_parameters(tmp_node, sgi_conf, list_index,
				err_msg, path);
			if (rc != EXIT_SUCCESS)
				goto out;
		}
	}
out:
	return rc;
}

int parse_ptp_time(xmlNode *node, char *err_msg, uint64_t *base_time,
	char *node_path)
{
	int rc = EXIT_SUCCESS;
	char *content;
	uint64_t tmp;
	char ele_val[MAX_ELEMENT_LENGTH];
	struct ieee_ptp_time admin_base_time = {0, 0};

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)node->name;
		if (strcmp(content, "seconds") == 0) {
			rc = xml_read_field(node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			rc = str_to_num(content, NUM_TYPE_U32, ele_val, &tmp,
					err_msg, node_path);
			if (rc < 0)
				goto out;
			admin_base_time.seconds = (uint32_t)tmp;
		} else if (strcmp(content, "nanoseconds") == 0) {
			/* defined by qci module */
			rc = xml_read_field(node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			rc = str_to_num(content, NUM_TYPE_U32, ele_val, &tmp,
					err_msg, node_path);
			if (rc < 0)
				goto out;
			if (tmp >= 1000000000) {
				sprintf(err_msg,
					"'%s' in '%s' should less than 10^9!",
					content, node_path);
				rc = EXIT_FAILURE;
				goto out;
			}
			admin_base_time.nano_seconds = (uint32_t) tmp;
		} else if (strcmp(content, "fractional-seconds") == 0) {
			/* defined by qbv module */
			rc = xml_read_field(node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			rc = str_to_num(content, NUM_TYPE_U32, ele_val, &tmp,
					err_msg, node_path);
			if (rc < 0)
				goto out;
			if (tmp >= 1000000000) {
				sprintf(err_msg,
					"'%s' in '%s' should less than 10^9!",
					content, node_path);
				rc = EXIT_FAILURE;
				goto out;
			}
			admin_base_time.nano_seconds = (uint32_t) tmp;
		}
	}
	*base_time = admin_base_time.nano_seconds + (admin_base_time.seconds*1000000000);

out:
	return rc;
}
int parse_stream_gate_table(xmlNode *node,
	struct std_qci_psfp_sgi_table *sgi_table,
	char *err_msg, char *node_path)
{
	int rc = EXIT_SUCCESS;
	char *content;
	uint32_t list_index = 0;
	uint64_t tmp;
	xmlNode *tmp_node;
	char ele_val[MAX_ELEMENT_LENGTH];
	char path[MAX_PATH_LENGTH];
	struct std_qci_psfp_sgi *cur_sgi_ptr = sgi_table->sgi_ptr;
	uint32_t list_len = 0;

	nc_verb_verbose("%s is called", __func__);
	/* Get admin-control-list-length node */
	tmp_node = get_child_node(node, "admin-control-list-length");
	if (!tmp_node) {
		goto pare_loop;
	}
	rc = xml_read_field(tmp_node, "admin-control-list-length",
			    ele_val, err_msg, node_path);
	if (rc != EXIT_SUCCESS)
		goto out;
	rc = str_to_num("admin-control-list-length", NUM_TYPE_U8, ele_val, &tmp,
			err_msg, node_path);
	if (rc < 0)
		goto out;
	cur_sgi_ptr->sgiconf.admin.control_list_length = (uint8_t)(tmp);
	list_len = (uint32_t)(tmp);
pare_loop:
	for (tmp_node = node->children; tmp_node != NULL;
	     tmp_node = tmp_node->next) {
		if (tmp_node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)tmp_node->name;
		if (strcmp(content, "stream-gate-instance-id") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			rc = str_to_num(content, NUM_TYPE_U32, ele_val, &tmp,
					err_msg, node_path);
			if (rc < 0)
				goto out;
			cur_sgi_ptr->sgi_handle = (uint32_t)tmp;
		} else if (strcmp(content, "gate-enable") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			if (strcmp(ele_val, "true") == 0) {
				sgi_table->sgi_ptr->enable = 1;
			} else if (strcmp(ele_val, "false") == 0) {
				sgi_table->sgi_ptr->enable = 0;
				return rc;
			} else {
				prt_err_bool(err_msg, content, node_path);
				rc = EXIT_FAILURE;
				goto out;
			}
		} else if (strcmp(content, "admin-gate-states") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;
			if (strcmp(ele_val, "open") == 0) {
				cur_sgi_ptr->sgiconf.admin.gate_states = TRUE;
			} else if (strcmp(ele_val, "closed") == 0) {
				cur_sgi_ptr->sgiconf.admin.gate_states = FALSE;
			} else {
				rc = EXIT_FAILURE;
				sprintf(err_msg, "unknown '%s' in '%s'!",
					content, node_path);
				goto out;
			}
		} else if (strcmp(content, "admin-ipv") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;
			if (strcmp(ele_val, "zero") == 0) {
				cur_sgi_ptr->sgiconf.admin.init_ipv = 0;
			} else if (strcmp(ele_val, "one") == 0) {
				cur_sgi_ptr->sgiconf.admin.init_ipv = 1;
			} else if (strcmp(ele_val, "two") == 0) {
				cur_sgi_ptr->sgiconf.admin.init_ipv = 2;
			} else if (strcmp(ele_val, "three") == 0) {
				cur_sgi_ptr->sgiconf.admin.init_ipv = 3;
			} else if (strcmp(ele_val, "four") == 0) {
				cur_sgi_ptr->sgiconf.admin.init_ipv = 4;
			} else if (strcmp(ele_val, "five") == 0) {
				cur_sgi_ptr->sgiconf.admin.init_ipv = 5;
			} else if (strcmp(ele_val, "six") == 0) {
				cur_sgi_ptr->sgiconf.admin.init_ipv = 6;
			} else if (strcmp(ele_val, "seven") == 0) {
				cur_sgi_ptr->sgiconf.admin.init_ipv = 7;
			} else if (strcmp(ele_val, "wildcard") == 0) {
				cur_sgi_ptr->sgiconf.admin.init_ipv = -1;
			} else {
				sprintf(err_msg,
					"'%s' in '%s' is out of range!",
					content, node_path);
				rc = EXIT_FAILURE;
				goto out;
			}
		} else if (strcmp(content, "admin-control-list") == 0) {
			if (list_index >= list_len)
				continue;
			strcpy(path, node_path);
			strcat(path, "/");
			strcat(path, content);
			rc = parse_admin_sgl(tmp_node, &cur_sgi_ptr->sgiconf,
					     list_index, err_msg, path);
			if (rc != EXIT_SUCCESS)
				goto out;

			list_index++;
		} else if (strcmp(content, "admin-cycle-time") == 0) {
			rc = get_cycle_time(tmp_node,
					    &cur_sgi_ptr->sgiconf.admin.cycle_time,
					    err_msg, path);
			if (rc != EXIT_SUCCESS)
				goto out;
		} else if (strcmp(content, "admin-cycle-time-extension") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			rc = str_to_num(content, NUM_TYPE_U32, ele_val, &tmp,
					err_msg, node_path);
			if (rc < 0)
				goto out;
			cur_sgi_ptr->sgiconf.admin.cycle_time_extension = (uint32_t)(tmp);
		} else if (strcmp(content, "admin-base-time") == 0) {
			strcpy(path, node_path);
			strcat(path, "/");
			strcat(path, content);
			rc = parse_ptp_time(tmp_node, err_msg,
					    (uint64_t *)&cur_sgi_ptr->sgiconf.admin.base_time,
					    path);
			if (rc != EXIT_SUCCESS)
				goto out;
		} else if (strcmp(content, "config-change") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			if (strcmp(ele_val, "true") == 0) {
				cur_sgi_ptr->sgiconf.config_change = TRUE;
			} else if (strcmp(ele_val, "false") == 0) {
				cur_sgi_ptr->sgiconf.config_change = FALSE;
			} else {
				prt_err_bool(err_msg, content, node_path);
				rc = EXIT_FAILURE;
				goto out;
			}
		} else if (strcmp(content, "gate-closed-due-to-invalid-rx-enable") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			if (strcmp(ele_val, "true") == 0) {
				cur_sgi_ptr->sgiconf.block_invalid_rx_enable = TRUE;
			} else if (strcmp(ele_val, "false") == 0) {
				cur_sgi_ptr->sgiconf.block_invalid_rx_enable = FALSE;
			} else {
				prt_err_bool(err_msg, content, node_path);
				rc = EXIT_FAILURE;
				goto out;
			}
		} else if (strcmp(content, "gate-closed-due-to-invalid-rx") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			if (strcmp(ele_val, "true") == 0) {
				cur_sgi_ptr->sgiconf.block_invalid_rx = TRUE;
			} else if (strcmp(ele_val, "false") == 0) {
				cur_sgi_ptr->sgiconf.block_invalid_rx = FALSE;
			} else {
				prt_err_bool(err_msg, content, node_path);
				rc = EXIT_FAILURE;
				goto out;
			}
		} else if (strcmp(content, "gate-closed-due-octets-exceeded-enable") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			if (strcmp(ele_val, "true") == 0) {
				cur_sgi_ptr->sgiconf.block_octets_exceeded_enable = TRUE;
			} else if (strcmp(ele_val, "false") == 0) {
				cur_sgi_ptr->sgiconf.block_octets_exceeded_enable = FALSE;
			} else {
				prt_err_bool(err_msg, content, node_path);
				rc = EXIT_FAILURE;
				goto out;
			}
		} else if (strcmp(content, "gate-closed-due-octets-exceeded") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			if (strcmp(ele_val, "true") == 0) {
				cur_sgi_ptr->sgiconf.block_octets_exceeded = TRUE;
			} else if (strcmp(ele_val, "false") == 0) {
				cur_sgi_ptr->sgiconf.block_octets_exceeded = FALSE;
			} else {
				prt_err_bool(err_msg, content, node_path);
				rc = EXIT_FAILURE;
				goto out;
			}
		}
	}
out:
	return rc;
}

int parse_stream_gates(xmlNode *node, struct std_qci_conf *qci_conf,
	char *err_msg, char *node_path)
{
	int rc = EXIT_SUCCESS;
	char *content;
	xmlNode *tmp_node;
	char path[MAX_PATH_LENGTH];
	struct std_qci_psfp_sgi_table *cur_sgi_table_ptr = NULL;

	nc_verb_verbose("%s is called", __func__);
	tmp_node = node;
	for (tmp_node = node->children; tmp_node != NULL;
	     tmp_node = tmp_node->next) {
		if (tmp_node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)tmp_node->name;
		if (strcmp(content, "stream-gate-instance-table") == 0) {
			if (qci_conf->sgi_table == NULL) {
				qci_conf->sgi_table = creat_new_sgi_instance();
				cur_sgi_table_ptr = qci_conf->sgi_table;
			} else {
				cur_sgi_table_ptr->next = creat_new_sgi_instance();
				cur_sgi_table_ptr = cur_sgi_table_ptr->next;
			}
			if (cur_sgi_table_ptr == NULL) {
				rc = EXIT_FAILURE;
				sprintf(err_msg,
					"allocate memory for '%s' failure!",
					content);
				goto out;
			}
			strcpy(path, node_path);
			strcat(path, "/");
			strcat(path, content);
			rc = parse_stream_gate_table(tmp_node,
						     cur_sgi_table_ptr,
						     err_msg, path);
			if (rc != EXIT_SUCCESS)
				goto out;
		}
	}
out:
	return rc;
}

int stream_gates_handle(char *portname, xmlNode *node,
	   char *err_msg, char *node_path)
{
	int rc = EXIT_SUCCESS;
	struct std_qci_conf qci_conf;
	struct std_qci_psfp_sgi_table *table = NULL;

	nc_verb_verbose("%s is called", __func__);
	/* Init qci configuration data */
	init_qci_memory(&qci_conf);

	rc = parse_stream_gates(node, &qci_conf, err_msg, node_path);
	if (rc != EXIT_SUCCESS)
		goto out;

	table = qci_conf.sgi_table;
	while (table != NULL) {
		/* set new flow meters configuration */
		rc = tsn_qci_psfp_sgi_set(portname,
					  table->sgi_ptr->sgi_handle,
					  table->sgi_ptr->enable,
					  &(table->sgi_ptr->sgiconf));
		if (rc != EXIT_SUCCESS) {
			sprintf(err_msg,
				"failed to set stream identification, %s!",
				strerror(-rc));
			goto out;
		}
		if (table->next == NULL)
			break;
		table = table->next;
	}
out:
	free_qci_memory(&qci_conf);
	return rc;
}

int parse_fm_table(xmlNode *node, struct std_qci_psfp_fmi_table *fmi_table,
	char *err_msg, char *node_path)
{
	int rc = EXIT_SUCCESS;
	char *content;
	uint64_t tmp;
	xmlNode *tmp_node;
	char ele_val[MAX_ELEMENT_LENGTH];
	struct std_qci_psfp_fmi *cur_fmi_ptr = fmi_table->fmi_ptr;

	nc_verb_verbose("%s is called", __func__);

	tmp_node = node;
	for (tmp_node = node->children; tmp_node != NULL;
	     tmp_node = tmp_node->next) {
		if (tmp_node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)tmp_node->name;
		if (strcmp(content, "flow-meter-instance-id") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			rc = str_to_num(content, NUM_TYPE_U32, ele_val, &tmp,
					err_msg, node_path);
			if (rc < 0)
				goto out;
			cur_fmi_ptr->fmi_id = (uint32_t)tmp;
		} else if (strcmp(content, "flow-meter-enabled") == 0) {
			rc = xml_read_field(tmp_node, content, ele_val,
					    err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			if (strcmp(ele_val, "true") == 0) {
				cur_fmi_ptr->enable = TRUE;
			} else if (strcmp(ele_val, "false") == 0) {
				cur_fmi_ptr->enable = FALSE;
			} else {
				prt_err_bool(err_msg, content, node_path);
				rc = EXIT_SUCCESS;
				goto out;
			}
		} else if (strcmp(content,
				  "committed-information-rate") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			rc = str_to_num(content, NUM_TYPE_U64, ele_val, &tmp,
					err_msg, node_path);
			if (rc < 0)
				goto out;
			tmp /= 1000;/* the units of cir in tsntool is kbit/s */
			if (tmp >= 2147483648) {/* 2^31 */
				rc = EXIT_FAILURE;
				sprintf(err_msg,
					"'%s' in '%s' out of range!",
					content, node_path);
				goto out;
			}
			cur_fmi_ptr->fmiconf.cir = (uint32_t)(tmp);
		} else if (strcmp(content, "committed-burst-size") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			rc = str_to_num(content, NUM_TYPE_U32, ele_val, &tmp,
					err_msg, node_path);
			if (rc < 0)
				goto out;
			cur_fmi_ptr->fmiconf.cbs = (uint32_t)(tmp);
		} else if (strcmp(content, "excess-information-rate") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			rc = str_to_num(content, NUM_TYPE_U64, ele_val, &tmp,
					err_msg, node_path);
			if (rc < 0)
				goto out;
			tmp /= 1000;/* the units of cir in tsntool is kbit/s */
			if (tmp >= 2147483648) {/* 2^31 */
				rc = EXIT_FAILURE;
				sprintf(err_msg,
					"'%s' in '%s' is out of range!",
					content, node_path);
				goto out;
			}
			cur_fmi_ptr->fmiconf.eir = (uint32_t)(tmp);
		} else if (strcmp(content, "excess-burst-size") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			rc = str_to_num(content, NUM_TYPE_U32, ele_val, &tmp,
					err_msg, node_path);
			if (rc < 0)
				goto out;
			cur_fmi_ptr->fmiconf.ebs = (uint32_t)(tmp);
		} else if (strcmp(content, "coupling-flag") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			if (strcmp(ele_val, "zero") == 0) {
				cur_fmi_ptr->fmiconf.cf = FALSE;
			} else if (strcmp(ele_val, "one") == 0) {
				cur_fmi_ptr->fmiconf.cf = TRUE;
			} else {
				sprintf(err_msg,
					"Invalid '%s' in '%s'!",
					content, node_path);
				rc = EXIT_FAILURE;
				goto out;
			}
		} else if (strcmp(content, "color-mode") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			if (strcmp(ele_val, "color-blind") == 0) {
				cur_fmi_ptr->fmiconf.cm = FALSE;
			} else if (strcmp(ele_val,
					  "color-aware") == 0) {
				cur_fmi_ptr->fmiconf.cm = TRUE;
			} else {
				sprintf(err_msg,
					"Invalid '%s' in '%s'!",
					content, node_path);
				rc = EXIT_FAILURE;
				goto out;
			}
		} else if (strcmp(content, "drop-on-yellow") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			if (strcmp(ele_val, "false") == 0) {
				cur_fmi_ptr->fmiconf.drop_on_yellow = FALSE;
			} else if (strcmp(ele_val, "true") == 0) {
				cur_fmi_ptr->fmiconf.drop_on_yellow = TRUE;
			} else {
				prt_err_bool(err_msg, content, node_path);
				rc = EXIT_FAILURE;
			}
		} else if (strcmp(content,
				  "mark-all-frames-red-enable") == 0) {
			rc = xml_read_field(tmp_node, content,
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;

			if (strcmp(ele_val, "false") == 0) {
				cur_fmi_ptr->fmiconf.mark_red_enable = FALSE;
			} else if (strcmp(ele_val, "true") == 0) {
				cur_fmi_ptr->fmiconf.mark_red_enable = TRUE;
			} else {
				prt_err_bool(err_msg, content, node_path);
				rc = EXIT_FAILURE;
			}
		}
	}
out:
	return rc;
}

int parse_flow_meters(xmlNode *node, struct std_qci_conf *qci_conf,
	char *err_msg, char *node_path)
{
	int rc = EXIT_SUCCESS;
	char *content;
	xmlNode *tmp_node;
	char path[MAX_PATH_LENGTH];
	struct std_qci_psfp_fmi_table *cur_fmi_table_ptr = qci_conf->fmi_table;

	nc_verb_verbose("%s is called", __func__);
	tmp_node = node;
	for (tmp_node = node->children; tmp_node != NULL;
	     tmp_node = tmp_node->next) {
		if (tmp_node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)tmp_node->name;
		if (strcmp(content, "flow-meter-instance-table") != 0)
			continue;

		if (qci_conf->fmi_table == NULL) {
			qci_conf->fmi_table = creat_new_fmi_instance();
			cur_fmi_table_ptr = qci_conf->fmi_table;
		} else {
			cur_fmi_table_ptr->next = creat_new_fmi_instance();
			cur_fmi_table_ptr = cur_fmi_table_ptr->next;
		}
		if (cur_fmi_table_ptr == NULL) {
			rc = EXIT_FAILURE;
			sprintf(err_msg,
				"allocate memory to '%s' failure!",
				content);
			goto out;
		}
		strcpy(path, node_path);
		strcat(path, "/");
		strcat(path, content);
		rc = parse_fm_table(tmp_node, cur_fmi_table_ptr,
				    err_msg, path);
		if (rc != EXIT_SUCCESS)
			goto out;
	}
out:
	return rc;
}

int flowmeters_handle(char *portname, xmlNode *node,
	   char *err_msg, char *node_path)
{
	int rc = EXIT_SUCCESS;
	struct std_qci_conf qci_conf;
	struct std_qci_psfp_fmi_table *table = NULL;

	nc_verb_verbose("%s is called", __func__);
	/* Init qci configuration data */
	init_qci_memory(&qci_conf);

	rc = parse_flow_meters(node, &qci_conf, err_msg, node_path);
	if (rc != EXIT_SUCCESS)
		goto out;

	table = qci_conf.fmi_table;
	while (table != NULL) {
		/* set new flow meters configuration */
		//nc_verb_verbose("cir is %d", table->fmi_ptr->fmiconf.cir);
		//nc_verb_verbose("cbs is %d", table->fmi_ptr->fmiconf.cbs);
		//nc_verb_verbose("eir is %d", table->fmi_ptr->fmiconf.eir);
		//nc_verb_verbose("ebs is %d", table->fmi_ptr->fmiconf.ebs);
		rc = tsn_qci_psfp_fmi_set(portname,
					  table->fmi_ptr->fmi_id,
					  table->fmi_ptr->enable,
					  &(table->fmi_ptr->fmiconf));
		if (rc != EXIT_SUCCESS) {
			sprintf(err_msg,
				"failed to set stream identification, %s!",
				strerror(-rc));
			goto out;
		}
		if (table->next == NULL)
			break;
		table = table->next;
	}
out:
	free_qci_memory(&qci_conf);
	return rc;
}

int probe_qci_sfi_xml_from_json(xmlNodePtr xml_node, cJSON *json_ob)
{
	int rc = 0;
	cJSON *item;
	xmlNodePtr tmp_node;
	char temp[80] = {0};
	int node_cnt = 0;
	uint64_t temp_ul = 0;
	char *tmp_str = NULL;

	nc_verb_verbose("%s is called", __func__);
	/* check if the flow meter is enabled */
	item = cJSON_GetObjectItem(json_ob, "disable");
	if (item)
		goto out;
	/* stream-filter-instance-id */
	item = cJSON_GetObjectItem(json_ob, "index");
	if (item) {
		temp_ul = ((uint64_t)item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		tmp_node = xmlNewChild(xml_node, NULL,
				       BAD_CAST "stream-filter-instance-id",
				       BAD_CAST temp);
		if (tmp_node == NULL) {
			rc = -1;
			goto out;
		}
		node_cnt++;
	}
	/* matching-frames-count */
	item = cJSON_GetObjectItem(json_ob, "match");
	if (item) {
		temp_ul = ((uint64_t)item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		tmp_node = xmlNewChild(xml_node, NULL,
				       BAD_CAST "matching-frames-count",
				       BAD_CAST temp);
		if (tmp_node == NULL) {
			rc = -1;
			goto out;
		}
		node_cnt++;
	}
	/* passing-frames-count */
	item = cJSON_GetObjectItem(json_ob, "pass");
	if (item) {
		temp_ul = ((uint64_t)item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		tmp_node = xmlNewChild(xml_node, NULL,
				       BAD_CAST "passing-frames-count",
				       BAD_CAST temp);
		if (tmp_node == NULL) {
			rc = -1;
			goto out;
		}
		node_cnt++;
	}
	/* not-passing-frames-count */
	item = cJSON_GetObjectItem(json_ob, "gate_drop");
	if (item) {
		temp_ul = ((uint64_t)item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		tmp_node = xmlNewChild(xml_node, NULL,
				       BAD_CAST "not-passing-frames-count",
				       BAD_CAST temp);
		if (tmp_node == NULL) {
			rc = -1;
			goto out;
		}
		node_cnt++;
	}
	/* passing-sdu-count */
	item = cJSON_GetObjectItem(json_ob, "sdu_pass");
	if (item) {
		temp_ul = ((uint64_t)item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		tmp_node = xmlNewChild(xml_node, NULL,
				       BAD_CAST "passing-sdu-count",
				       BAD_CAST temp);
		if (tmp_node == NULL) {
			rc = -1;
			goto out;
		}
		node_cnt++;
	}
	/* not-passing-sdu-count */
	item = cJSON_GetObjectItem(json_ob, "sdu_drop");
	if (item) {
		temp_ul = ((uint64_t)item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		tmp_node = xmlNewChild(xml_node, NULL,
				       BAD_CAST "not-passing-sdu-count",
				       BAD_CAST temp);
		if (tmp_node == NULL) {
			rc = -1;
			goto out;
		}
		node_cnt++;
	}
	/* red-frames-count */
	item = cJSON_GetObjectItem(json_ob, "red");
	if (item) {
		temp_ul = ((uint64_t)item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		tmp_node = xmlNewChild(xml_node, NULL,
				       BAD_CAST "red-frames-count",
				       BAD_CAST temp);
		if (tmp_node == NULL) {
			rc = -1;
			goto out;
		}
		node_cnt++;
	}
	/* stream-blocked-due-to-oversize-frame */
	item = cJSON_GetObjectItem(json_ob, "oversize");
	if (item) {
		tmp_str = item->valuestring;
		if (strcmp(tmp_str, "ON") == 0) {
			tmp_node = xmlNewChild(xml_node, NULL,
					       BAD_CAST "stream-blocked-due-to-oversize-frame",
					       BAD_CAST "true");
			if (tmp_node == NULL) {
				rc = -1;
				goto out;
			}
			node_cnt++;
		} else {
			tmp_node = xmlNewChild(xml_node, NULL,
					       BAD_CAST "stream-blocked-due-to-oversize-frame",
					       BAD_CAST "false");
			if (tmp_node == NULL) {
				rc = -1;
				goto out;
			}
			node_cnt++;
		}
	} else {
		tmp_node = xmlNewChild(xml_node, NULL,
				       BAD_CAST "stream-blocked-due-to-oversize-frame",
				       BAD_CAST "false");
		if (tmp_node == NULL) {
			rc = -1;
			goto out;
		}
		node_cnt++;
	}
out:
	if (rc >= 0)
		rc = node_cnt;
	return rc;
}

int probe_qci_sgi_xml_from_json(xmlNodePtr xml_node, cJSON *json_ob)
{
	int rc = 0;
	xmlNodePtr tmp_node;
	xmlNodePtr time_node;
	char temp[80] = {0};
	cJSON *item;
	int node_cnt = 0;

	uint64_t second = 0;
	uint64_t nanosecond = 0;
	uint64_t temp_ul = 0;

	nc_verb_verbose("%s is called", __func__);
	/* check if the flow meter is enabled */
	item = cJSON_GetObjectItem(json_ob, "disable");
	if (item)
		goto out;
	/* stream-filter-instance-id */
	item = cJSON_GetObjectItem(json_ob, "index");
	if (item) {
		temp_ul = ((uint64_t)item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		tmp_node = xmlNewChild(xml_node, NULL,
				       BAD_CAST "stream-gate-instance-id",
				       BAD_CAST temp);
		if (tmp_node == NULL) {
			rc = -1;
			goto out;
		}
		node_cnt++;
	}
	/* max-stream-gate-instances */

	/* config-change-time */
	item = cJSON_GetObjectItem(json_ob, "configchange time");
	if (item) {
		second = ((uint64_t)item->valuedouble/1000000000);
		nanosecond = ((uint64_t)item->valuedouble%1000000000);
		time_node = xmlNewChild(xml_node, NULL,
				       BAD_CAST "config-change-time", NULL);
		sprintf(temp, "%ld", second);
		xmlNewTextChild(time_node, NULL,
				       BAD_CAST "seconds", BAD_CAST temp);
		sprintf(temp, "%ld", nanosecond);
		xmlNewTextChild(time_node, NULL,
				       BAD_CAST "nanoseconds", BAD_CAST temp);
		node_cnt++;
	}
	/* tick-granularity */
	item = cJSON_GetObjectItem(json_ob, "tick");
	if (item) {
		temp_ul = ((uint64_t)item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		tmp_node = xmlNewChild(xml_node, NULL,
				       BAD_CAST "tick-granularity",
				       BAD_CAST temp);
		if (tmp_node == NULL) {
			rc = -1;
			goto out;
		}
		node_cnt++;
	}
	/* current-time */
	item = cJSON_GetObjectItem(json_ob, "currenttime");
	if (item) {
		second = ((uint64_t)item->valuedouble/1000000000);
		nanosecond = ((uint64_t)item->valuedouble%1000000000);
		time_node = xmlNewChild(xml_node, NULL,
				       BAD_CAST "current-time", NULL);
		sprintf(temp, "%ld", second);
		xmlNewTextChild(time_node, NULL,
				       BAD_CAST "seconds", BAD_CAST temp);
		sprintf(temp, "%ld", nanosecond);
		xmlNewTextChild(time_node, NULL,
				BAD_CAST "nanoseconds", BAD_CAST temp);
		node_cnt++;
	}
	/* config-pending */
	item = cJSON_GetObjectItem(json_ob, "config pending");
	if (item) {
		tmp_node = xmlNewChild(xml_node, NULL,
				       BAD_CAST "config-pending",
				       BAD_CAST "true");
		if (tmp_node == NULL) {
			rc = -1;
			goto out;
		}
		node_cnt++;
	}
	/* config-change-error */
	item = cJSON_GetObjectItem(json_ob, "configchange error");
	if (item) {
		tmp_node = xmlNewChild(xml_node, NULL,
				       BAD_CAST "config-change-error",
				       BAD_CAST "true");
		if (tmp_node == NULL) {
			rc = -1;
			goto out;
		}
		node_cnt++;
	}
	/* supported-list-max */
	/* oper-gate-states */
	/* oper-ipv */
	/* oper-control-list-length */
	/* oper-cycle-time */
	/* oper-cycle-time-extension */
	/* oper-base-time */
	/* oper-control-list */
out:
	if (rc >= 0)
		rc = node_cnt;
	return rc;
}

int probe_qci_fmi_xml_from_json(xmlNodePtr xml_node, cJSON *json_ob)
{
	int rc = 0;
	xmlNodePtr tmp_node;
	char temp[80] = {0};
	cJSON *item;
	int node_cnt = 0;

	uint64_t temp_ul = 0;

	nc_verb_verbose("%s is called", __func__);
	/* check if the flow meter is enabled */
	item = cJSON_GetObjectItem(json_ob, "disable");
	if (item)
		goto out;
	/* stream-filter-instance-id */
	item = cJSON_GetObjectItem(json_ob, "index");
	if (item) {
		temp_ul = ((uint64_t)item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		tmp_node = xmlNewChild(xml_node, NULL,
				       BAD_CAST "flow-meter-instance-id",
				       BAD_CAST temp);
		if (tmp_node == NULL) {
			rc = -1;
			goto out;
		}
		node_cnt++;
	}
	/* mark-all-frames-red */
	item = cJSON_GetObjectItem(json_ob, "mark red enable");
	if (item) {
		tmp_node = xmlNewChild(xml_node, NULL,
				       BAD_CAST "mark-all-frames-red",
				       BAD_CAST "true");
		if (tmp_node == NULL) {
			rc = -1;
			goto out;
		}
		node_cnt++;
	} else {
		tmp_node = xmlNewChild(xml_node, NULL,
				       BAD_CAST "mark-all-frames-red",
				       BAD_CAST "false");
		if (tmp_node == NULL) {
			rc = -1;
			goto out;
		}
		node_cnt++;
	}
out:
	if (rc >= 0)
		rc = node_cnt;
	return 0;
}

int get_qci_stream_filter_instance_status(char *port, xmlNodePtr para_node,
	int sfid)
{
	int rc = EXIT_SUCCESS;
	FILE *fp;
	int len = 0;
	cJSON *json;
	char *json_data;
	struct tsn_qci_psfp_sfi_conf sfi_struct;
	int cnt = 0;

	rc = tsn_qci_psfp_sfi_get(port, sfid, &sfi_struct);

	if (rc < 0)
		goto out;

	fp = fopen(TSNTOOL_PORT_ST_FILE, "r");
	if (fp == NULL) {
		nc_verb_verbose("open '%s' error", TSNTOOL_PORT_ST_FILE);
	} else {
		fseek(fp, 0, SEEK_END);
		len = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		json_data = (char *)malloc(len+1);
		if (json_data) {
			fread(json_data, 1, len, fp);
			json = cJSON_Parse(json_data);
			if (json)
				cnt = probe_qci_sfi_xml_from_json(para_node,
								  json);
			else
				nc_verb_verbose("json parse error");
			cJSON_Delete(json);
			free(json_data);
		} else {
			nc_verb_verbose("malloc error");
		}
		fclose(fp);
	}
	//sprintf(name, "/tmp/sfi_%d.json", sfid);
	//rename(TSNTOOL_PORT_ST_FILE, name);
out:
	if (rc >= 0)
		rc = cnt;
	return rc;
}
int get_qci_stream_filters_status(char *port, xmlNodePtr para_node,
	int max_list_num)
{
	int rc = EXIT_SUCCESS;
	xmlNode *table_node;
	int sfid;
	int cnt;
	xmlDocPtr sub_doc = NULL;
	char node_name[MAX_ELEMENT_LENGTH];

	nc_verb_verbose("%s is called", __func__);
	for (sfid = 0; sfid < max_list_num; sfid++) {
		sprintf(node_name, "stream-filter-instance-table");
		table_node = create_root_in_doc_no_ns(sub_doc, node_name);
		if (table_node == NULL) {
			rc = EXIT_FAILURE;
			nc_verb_verbose("create table node failure");
			goto out;
		}
		cnt = get_qci_stream_filter_instance_status(port, table_node,
						      sfid);
		if (cnt > 0)
			xmlAddChild(para_node, table_node);
		free_doc_mem(sub_doc);
	}
out:
	return rc;
}

int get_qci_stream_gate_instance_status(char *port, xmlNodePtr para_node,
	int sgid)
{
	int rc = EXIT_SUCCESS;
	FILE *fp;
	int len = 0;
	cJSON *json;
	char *json_data;
	struct tsn_qci_psfp_sgi_conf sgi_struct;
	int cnt = 0;

	rc = tsn_qci_psfp_sgi_get(port, sgid, &sgi_struct);

	if (rc < 0)
		goto out;

	fp = fopen(TSNTOOL_PORT_ST_FILE, "r");
	if (fp == NULL) {
		nc_verb_verbose("open '%s' error", TSNTOOL_PORT_ST_FILE);
	} else {
		fseek(fp, 0, SEEK_END);
		len = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		json_data = (char *)malloc(len+1);
		if (json_data) {
			fread(json_data, 1, len, fp);
			json = cJSON_Parse(json_data);
			if (json)
				cnt = probe_qci_sgi_xml_from_json(para_node,
								  json);
			else
				nc_verb_verbose("json parse error");
			cJSON_Delete(json);
			free(json_data);
		} else {
			nc_verb_verbose("malloc error");
		}
		fclose(fp);
	}
	//sprintf(name, "/root/sgi_%d.json", sgid);
	//rename(TSNTOOL_PORT_ST_FILE, name);
out:
	if (rc > 0)
		rc = cnt;
	return rc;
}
int get_qci_stream_gates_status(char *port, xmlNodePtr para_node,
	int max_list_num)
{
	int rc = EXIT_SUCCESS;
	xmlNodePtr table_node;
	int sgid;
	int cnt;
	xmlDocPtr sub_doc = NULL;
	char node_name[MAX_ELEMENT_LENGTH];

	for (sgid = 0; sgid < max_list_num; sgid++) {
		usleep(1000);
		sprintf(node_name, "stream-gate-instance-table");
		table_node = create_root_in_doc_no_ns(sub_doc, node_name);
		if (table_node == NULL) {
			rc = EXIT_FAILURE;
			goto out;
		}

		cnt = get_qci_stream_gate_instance_status(port, table_node,
							  sgid);
		if (cnt > 0)
			xmlAddChild(para_node, table_node);
		free_doc_mem(sub_doc);
	}
out:
	return rc;
}

int get_qci_flow_meter_instance_status(char *port, xmlNodePtr para_node,
	int fmid)
{
	int rc = EXIT_SUCCESS;
	FILE *fp;
	int len = 0;
	cJSON *json;
	char *json_data;
	struct tsn_qci_psfp_fmi fmi_struct;

	nc_verb_verbose("%s is called", __func__);

	rc = tsn_qci_psfp_fmi_get(port, fmid, &fmi_struct);
	if (rc < 0) {
		nc_verb_verbose("fmi get err");
		goto out;
	}

	fp = fopen(TSNTOOL_PORT_ST_FILE, "r");
	if (fp == NULL) {
		nc_verb_verbose("open '%s' error", TSNTOOL_PORT_ST_FILE);
	} else {
		fseek(fp, 0, SEEK_END);
		len = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		json_data = (char *)malloc(len+1);
		if (json_data) {
			fread(json_data, 1, len, fp);
			json = cJSON_Parse(json_data);
			if (json)
				probe_qci_fmi_xml_from_json(para_node, json);
			else
				nc_verb_verbose("json parse error");
			cJSON_Delete(json);
			free(json_data);
		} else {
			nc_verb_verbose("malloc error");
		}
		fclose(fp);
	}
	//sprintf(name, "/root/fmi_%d.json", fmid);
	//rename(TSNTOOL_PORT_ST_FILE, name);
out:
	return rc;
}

int get_qci_flow_meters_status(char *port, xmlNodePtr para_node,
	int max_list_num)
{
	int rc = EXIT_SUCCESS;
	int fmid;
	xmlNode *table_node;
	int cnt;
	xmlDocPtr sub_doc = NULL;
	char node_name[MAX_ELEMENT_LENGTH];

	nc_verb_verbose("%s is called", __func__);

	for (fmid = 0; fmid < max_list_num; fmid++) {
		sprintf(node_name, "flow-meter-instance-table");
		table_node = create_root_in_doc_no_ns(sub_doc, node_name);
		if (table_node == NULL) {
			rc = EXIT_FAILURE;
			goto out;
		}

		cnt = get_qci_flow_meter_instance_status(port, table_node,
							 fmid);
		if (cnt > 0)
			xmlAddChild(para_node, table_node);
		free_doc_mem(sub_doc);
	}
out:
	return rc;
}

int get_sfi_config(char *port, xmlNodePtr node, int mode, uint32_t index)
{
	int rc = EXIT_SUCCESS;
	FILE *fp;
	int len = 8;
	cJSON *json, *item;
	char temp[80] = {0};
	xmlNodePtr sfi_node, table_node, filter_list;
	cJSON *over_en, *max_sdu, *flow_id;
	char *json_data;
	struct tsn_qci_psfp_sfi_conf sfi;
	uint64_t temp_ul = 0;
	int8_t pri;
	xmlNsPtr ns;

	nc_verb_verbose("%s is called", __func__);
	init_tsn_socket();
	rc = tsn_qci_psfp_sfi_get(port, index, &sfi);
	close_tsn_socket();
	if (rc < 0)
		return rc;

	/* Get json node */
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
		nc_verb_verbose("alloc memory for json failed");
		rc = EXIT_FAILURE;
		goto out1;
	}
	fread(json_data, 1, len, fp);
	json = cJSON_Parse(json_data);
	if (!json) {
		nc_verb_verbose("parse json data failed");
		rc = EXIT_FAILURE;
		goto out2;
	}

	sfi_node = xmlNewChild(node, NULL, BAD_CAST "stream-filters", NULL);
	ns = xmlNewNs(sfi_node, BAD_CAST SFSG_NS, BAD_CAST SFSG_PREFIX);
	xmlSetNs(sfi_node, ns);
	ns = xmlNewNs(sfi_node, BAD_CAST QCI_AUGMENT_NS,
		      BAD_CAST QCI_AUGMENT_PREFIX);
	table_node = xmlNewChild(sfi_node, NULL,
			       BAD_CAST "stream-filter-instance-table", NULL);
	if (table_node == NULL) {
		rc = EXIT_FAILURE;
		goto out3;
	}
	/* stream-filter-instance-id */
	item = cJSON_GetObjectItem(json, "index");
	if (item) {
		temp_ul = ((uint64_t)item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		xmlNewChild(table_node, NULL,
			    BAD_CAST "stream-filter-instance-id",
			    BAD_CAST temp);
	}
	/* enable */
	item = cJSON_GetObjectItem(json, "enable");
	if (item) {
		xmlNewChild(table_node, ns, BAD_CAST "stream-filter-enabled",
			    BAD_CAST "true");
	} else {
		xmlNewChild(table_node, ns, BAD_CAST "stream-filter-enabled",
			    BAD_CAST "false");
		goto out3;
	}
	/* streamhandle */
	item = cJSON_GetObjectItem(json, "streamhandle");
	if (item) {
		temp_ul = ((uint64_t)item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		xmlNewChild(table_node, NULL, BAD_CAST "stream-handle",
			    BAD_CAST temp);
	}
	/* priority */
	item = cJSON_GetObjectItem(json, "priority");
	if (item) {
		pri = ((int8_t)item->valuedouble);
		pri_int2yangstr(pri, temp);
		xmlNewChild(table_node, NULL, BAD_CAST "priority-spec",
			    BAD_CAST temp);
	}
	/* gateid */
	item = cJSON_GetObjectItem(json, "gateid");
	if (item) {
		temp_ul = ((uint64_t)item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		xmlNewChild(table_node, NULL, BAD_CAST "stream-gate-ref",
			    BAD_CAST temp);
	}
	/* filter specification list */
	max_sdu = cJSON_GetObjectItem(json, "maxsdu");
	over_en = cJSON_GetObjectItem(json, "oversize enable");
	flow_id = cJSON_GetObjectItem(json, "flowid");
	if (max_sdu || over_en || flow_id) {
		filter_list = xmlNewChild(table_node, NULL,
			    BAD_CAST "filter-specification-list", NULL);
		if (!filter_list)
			goto out3;

		xmlNewTextChild(filter_list, NULL,
			    BAD_CAST "index", BAD_CAST "0");
		if (max_sdu) {
			temp_ul = ((uint64_t)max_sdu->valuedouble);
			sprintf(temp, "%ld", temp_ul);
			xmlNewChild(filter_list, NULL,
				    BAD_CAST "maximum-sdu-size",
				    BAD_CAST temp);
		}
		/* flow meter id */
		if (flow_id) {
			temp_ul = ((uint64_t)flow_id->valuedouble);
			sprintf(temp, "%ld", temp_ul);
			xmlNewChild(filter_list, NULL,
				    BAD_CAST "flow-meter-ref",
				    BAD_CAST temp);
		}
		sprintf(temp, "stream-blocked-due-to-oversize-frame-enabled");
		if (over_en)
			xmlNewChild(filter_list, NULL, BAD_CAST temp,
				    BAD_CAST "true");
		else
			xmlNewChild(filter_list, NULL, BAD_CAST temp,
				    BAD_CAST "false");
	}
out3:
	cJSON_Delete(json);
out2:
	free(json_data);
out1:
	fclose(fp);
out:
	return rc;
}

int get_sgi_config(char *port, xmlNodePtr node, int mode, uint32_t index)
{
	int rc = EXIT_SUCCESS;
	FILE *fp;
	int len = 0, i;
	cJSON *json, *item, *admin, *gcl;
	char temp[80] = {0};
	xmlNodePtr sgi_node, table_node, temp_node;
	xmlNodePtr para_node, time_node;
	xmlNodePtr gcl_node;
	char *json_data;
	uint64_t temp_ul = 0, second = 0, nanosecond = 0;
	struct tsn_qci_psfp_sgi_conf sgi;
	xmlNsPtr sfsg_ns;
	xmlNsPtr psfp_ns;
	int8_t pri;

	nc_verb_verbose("%s is called", __func__);
	init_tsn_socket();
	rc = tsn_qci_psfp_sgi_get(port, index, &sgi);
	close_tsn_socket();
	if (rc < 0)
		return rc;

	/* Get json node */
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
		nc_verb_verbose("alloc memory for json failed");
		rc = EXIT_FAILURE;
		goto out1;
	}
	fread(json_data, 1, len, fp);
	json = cJSON_Parse(json_data);
	if (!json) {
		nc_verb_verbose("parse json data failed");
		rc = EXIT_FAILURE;
		goto out2;
	}

	sgi_node = xmlNewChild(node, NULL, BAD_CAST "stream-gates", NULL);
	sfsg_ns = xmlNewNs(sgi_node, BAD_CAST SFSG_NS, BAD_CAST SFSG_PREFIX);
	psfp_ns = xmlNewNs(sgi_node, BAD_CAST PSFP_NS, BAD_CAST PSFP_PREFIX);
	xmlSetNs(sgi_node, sfsg_ns);
	table_node = xmlNewChild(sgi_node, sfsg_ns,
			       BAD_CAST "stream-gate-instance-table", NULL);
	if (table_node == NULL) {
		rc = EXIT_FAILURE;
		goto out3;
	}
	/* stream-gate-instance-id */
	item = cJSON_GetObjectItem(json, "index");
	if (item) {
		temp_ul = ((uint64_t)item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		xmlNewChild(table_node, sfsg_ns,
			    BAD_CAST "stream-gate-instance-id",
			    BAD_CAST temp);
	}
	/* gate-enable */
	item = cJSON_GetObjectItem(json, "enable");
	if (item) {
		xmlNewChild(table_node, sfsg_ns,
			    BAD_CAST "gate-enable", BAD_CAST "true");
	} else {
		xmlNewChild(table_node, sfsg_ns,
			    BAD_CAST "gate-enable", BAD_CAST "false");
		goto out3;
	}
	admin = cJSON_GetObjectItem(json, "adminentry");
	if (!admin)
		goto out3;

	/* admin-gate-states */
	item = cJSON_GetObjectItem(admin, "initial state");
	if (item)
		xmlNewChild(table_node, sfsg_ns, BAD_CAST "admin-gate-states",
			    BAD_CAST "true");
	else
		xmlNewChild(table_node, sfsg_ns, BAD_CAST "admin-gate-states",
			    BAD_CAST "false");
	/* admin-ipv */
	item = cJSON_GetObjectItem(admin, "initial ipv");
	if (item) {
		pri = ((int8_t)item->valuedouble);
		pri_int2yangstr(pri, temp);
		xmlNewChild(table_node, sfsg_ns, BAD_CAST "admin-ipv",
			    BAD_CAST temp);
	}
	/* admin-control-list-length */
	item = cJSON_GetObjectItem(admin, "length");
	if (item) {
		len = ((int)item->valuedouble);
		sprintf(temp, "%d", len);
		xmlNewChild(table_node, psfp_ns,
			    BAD_CAST "admin-control-list-length",
			    BAD_CAST temp);
	}
	/* admin-cycle-time */
	item = cJSON_GetObjectItem(admin, "cycle time");
	if (item) {
		temp_node = xmlNewChild(table_node, psfp_ns,
					BAD_CAST "admin-cycle-time",
					NULL);
		temp_ul = (uint64_t)(item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		xmlNewTextChild(temp_node, NULL, BAD_CAST "numerator",
				BAD_CAST temp);
		xmlNewTextChild(temp_node, NULL,
				BAD_CAST "denominator",
				BAD_CAST "1000000000");
	}
	/* admin-cycle-time-extension */
	item = cJSON_GetObjectItem(admin, "cycle time extend");
	if (item) {
		temp_ul = ((uint64_t)item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		xmlNewChild(table_node, psfp_ns,
			    BAD_CAST "admin-cycle-time-extension",
			    BAD_CAST temp);
	}
	/* basetime */
	item = cJSON_GetObjectItem(admin, "basetime");
	if (item) {
		second = ((uint64_t)item->valuedouble/1000000000);
		nanosecond = ((uint64_t)item->valuedouble%1000000000);
		time_node = xmlNewChild(table_node, psfp_ns,
					BAD_CAST "admin-base-time",
					NULL);
		sprintf(temp, "%ld", second);
		xmlNewTextChild(time_node, psfp_ns, BAD_CAST "seconds",
				BAD_CAST temp);
		sprintf(temp, "%ld", nanosecond);
		xmlNewTextChild(time_node, NULL,
				BAD_CAST "nanoseconds",
				BAD_CAST temp);
	}
	/* control list */
	for (i = 0; i < len; i++) {
		gcl = get_list_item(admin, "gatelist", i);
		if (!gcl)
			break;
		gcl_node = xmlNewChild(table_node, psfp_ns,
				       BAD_CAST "admin-control-list",
				       BAD_CAST NULL);
		sprintf(temp, "%d", i);
		xmlNewTextChild(gcl_node, NULL, BAD_CAST "index",
				BAD_CAST temp);
		xmlNewTextChild(gcl_node, NULL, BAD_CAST "operation-name",
				BAD_CAST "psfp:set-gate-and-ipv");
		para_node = xmlNewChild(gcl_node, NULL,
					BAD_CAST "parameters", NULL);
		item = cJSON_GetObjectItem(gcl, "gate state");
		if (item)
			xmlNewChild(para_node, NULL,
				    BAD_CAST "gate-state-value",
				    BAD_CAST "open");
		else
			xmlNewChild(para_node, NULL,
				    BAD_CAST "gate-state-value",
				    BAD_CAST "closed");

		item = cJSON_GetObjectItem(gcl, "ipv");
		if (item) {
			pri = ((int8_t)item->valuedouble);
			pri_int2yangstr(pri, temp);
			xmlNewChild(para_node, NULL,
				    BAD_CAST "ipv-value",
				    BAD_CAST temp);
		}

		item = cJSON_GetObjectItem(gcl, "time interval");
		if (item) {
			temp_ul = ((uint64_t)item->valuedouble);
			sprintf(temp, "%ld", temp_ul);
			xmlNewChild(para_node, NULL,
				    BAD_CAST "time-interval-value",
				    BAD_CAST temp);
		}

		item = cJSON_GetObjectItem(gcl, "octmax");
		if (item) {
			temp_ul = ((uint64_t)item->valuedouble);
			sprintf(temp, "%ld", temp_ul);
			xmlNewChild(para_node, NULL,
				    BAD_CAST "interval-octet-max",
				    BAD_CAST temp);
		}
	}

out3:
	cJSON_Delete(json);
out2:
	free(json_data);
out1:
	fclose(fp);
out:
	return rc;
}

int get_fmi_config(char *port, xmlNodePtr node, int mode, uint32_t index)
{
	int rc = EXIT_SUCCESS;
	FILE *fp;
	int len = 0;
	cJSON *json, *item;
	char temp[80] = {0};
	xmlNodePtr fmi_node, table_node;
	char *json_data;
	struct tsn_qci_psfp_fmi fmi;
	uint64_t temp_ul = 0;
	uint64_t cir = 0, cbs = 0, eir = 0, ebs = 0;
	xmlNsPtr ns;
	int cnt = 0;

	nc_verb_verbose("%s is called", __func__);
	init_tsn_socket();
	rc = tsn_qci_psfp_fmi_get(port, index, &fmi);
	close_tsn_socket();
	if (rc < 0)
		return rc;

	/* Get json node */
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
		nc_verb_verbose("alloc memory for json failed");
		rc = EXIT_FAILURE;
		goto out1;
	}
	fread(json_data, 1, len, fp);
	json = cJSON_Parse(json_data);
	if (!json) {
		nc_verb_verbose("parse json data failed");
		rc = EXIT_FAILURE;
		goto out2;
	}

	fmi_node = xmlNewChild(node, NULL, BAD_CAST "flow-meters", NULL);
	ns = xmlNewNs(fmi_node, BAD_CAST PSFP_NS, BAD_CAST PSFP_PREFIX);
	xmlSetNs(fmi_node, ns);
	ns = xmlNewNs(fmi_node, BAD_CAST QCI_AUGMENT_NS,
		      BAD_CAST QCI_AUGMENT_PREFIX);
	table_node = xmlNewChild(fmi_node, NULL,
			       BAD_CAST "flow-meter-instance-table", NULL);
	if (table_node == NULL) {
		rc = EXIT_FAILURE;
		goto out3;
	}
	/* flow-meter-instance-id */
	item = cJSON_GetObjectItem(json, "index");
	if (item) {
		temp_ul = ((uint64_t)item->valuedouble);
		sprintf(temp, "%ld", temp_ul);
		xmlNewChild(table_node, NULL, BAD_CAST "flow-meter-instance-id",
			    BAD_CAST temp);
	}
	/* cir */
	item = cJSON_GetObjectItem(json, "cir");
	if (item) {
		cir = ((uint64_t)item->valuedouble);
		cir *= 1000;
		if (cir)
			cnt++;
	}
	/* cbs */
	item = cJSON_GetObjectItem(json, "cbs");
	if (item) {
		cbs = ((uint64_t)item->valuedouble);
		if (cbs)
			cnt++;
	}
	/* eir */
	item = cJSON_GetObjectItem(json, "eir");
	if (item) {
		eir = ((uint64_t)item->valuedouble);
		eir *= 1000;
		if (eir)
			cnt++;
	}
	/* ebs */
	item = cJSON_GetObjectItem(json, "ebs");
	if (item) {
		ebs = ((uint64_t)item->valuedouble);
		if (ebs)
			cnt++;
	}
	/* flow-meter-enabled */
	if (cnt) {
		xmlNewChild(table_node, ns,
			    BAD_CAST "flow-meter-enabled",
			    BAD_CAST "true");
		sprintf(temp, "%ld", cir);
		xmlNewChild(table_node, NULL,
			    BAD_CAST "committed-information-rate",
			    BAD_CAST temp);
		sprintf(temp, "%ld", cbs);
		xmlNewChild(table_node, NULL,
			    BAD_CAST "committed-burst-size",
			    BAD_CAST temp);
		sprintf(temp, "%ld", eir);
		xmlNewChild(table_node, NULL,
			    BAD_CAST "excess-information-rate",
			    BAD_CAST temp);
		sprintf(temp, "%ld", ebs);
		xmlNewChild(table_node, NULL,
			    BAD_CAST "excess-burst-size",
			    BAD_CAST temp);
	} else {
		xmlNewChild(table_node, ns,
			    BAD_CAST "flow-meter-enabled",
			    BAD_CAST "false");
		goto out3;
	}
	/* couple flag */
	item = cJSON_GetObjectItem(json, "couple flag");
	if (item)
		xmlNewChild(table_node, NULL, BAD_CAST "coupling-flag",
			    BAD_CAST "Coupled");
	else
		xmlNewChild(table_node, NULL, BAD_CAST "coupling-flag",
			    BAD_CAST "Uncoupled");
	/* couple mode */
	item = cJSON_GetObjectItem(json, "color mode");
	if (item)
		xmlNewChild(table_node, NULL, BAD_CAST "color-mode",
			    BAD_CAST "color-aware");
	else
		xmlNewChild(table_node, NULL, BAD_CAST "color-mode",
			    BAD_CAST "color-blind");
	/* drop-on-yellow */
	item = cJSON_GetObjectItem(json, "drop yellow");
	if (item)
		xmlNewChild(table_node, NULL, BAD_CAST "drop-on-yellow",
			    BAD_CAST "true");
	else
		xmlNewChild(table_node, NULL, BAD_CAST "drop-on-yellow",
			    BAD_CAST "false");
	/* mark-all-frames-red-enable */
	item = cJSON_GetObjectItem(json, "mark red enable");
	if (item)
		xmlNewChild(table_node, NULL,
			    BAD_CAST "mark-all-frames-red-enable",
			    BAD_CAST "true");
	else
		xmlNewChild(table_node, NULL,
			    BAD_CAST "mark-all-frames-red-enable",
			    BAD_CAST "false");
out3:
	cJSON_Delete(json);
out2:
	free(json_data);
out1:
	fclose(fp);
out:
	return rc;
}

int get_qci_status(char *port, xmlNodePtr node)
{
	int rc = EXIT_SUCCESS;
	xmlNodePtr qci_sf_st_node;
	xmlNodePtr qci_sg_st_node;
	xmlNodePtr qci_fm_st_node;
	xmlNsPtr ns;
	int max_list_num;
	xmlNodePtr max_list_node;
	struct tsn_qci_psfp_stream_param qci_max_cap = {0};
	char temp[80] = {0};

	nc_verb_verbose("%s is called", __func__);

	if (port == NULL)
		return EXIT_FAILURE;

	/* get qci instance max capability */
	genl_tsn_init();
	if (tsn_qci_streampara_get(port, &qci_max_cap) < 0) {
		nc_verb_verbose("get qci cap fail");
		goto out;
	}
	qci_sf_st_node = xmlNewChild(node, NULL, BAD_CAST "stream-filters",
				     NULL);
	if (qci_sf_st_node == NULL) {
		rc = EXIT_FAILURE;
		nc_verb_verbose("stream-filters node create fail");
		goto out;
	}
	ns = xmlNewNs(qci_sf_st_node, BAD_CAST SFSG_NS, BAD_CAST SFSG_PREFIX);
	xmlSetNs(qci_sf_st_node, ns);
	max_list_num = qci_max_cap.max_sf_instance;
	sprintf(temp, "%d", max_list_num);
	max_list_node = xmlNewChild(qci_sf_st_node, NULL,
				    BAD_CAST "max-stream-filter-instances",
				    BAD_CAST temp);
	if (max_list_node == NULL) {
		rc = EXIT_FAILURE;
		nc_verb_verbose("max_list_node node create fail");
		goto out;
	} else {
		rc = get_qci_stream_filters_status(port, qci_sf_st_node,
						  max_list_num);
		if (rc != EXIT_SUCCESS)
			goto out;
	}
	qci_sg_st_node = xmlNewChild(node, NULL,
				     BAD_CAST "stream-gates", NULL);
	if (qci_sg_st_node == NULL) {
		rc = EXIT_FAILURE;
		goto out;
	}
	ns = xmlNewNs(qci_sg_st_node, BAD_CAST SFSG_NS, BAD_CAST SFSG_PREFIX);
	xmlSetNs(qci_sg_st_node, ns);

	max_list_num = qci_max_cap.max_sg_instance;
	sprintf(temp, "%d", max_list_num);
	max_list_node = xmlNewChild(qci_sg_st_node, NULL,
				    BAD_CAST "max-stream-gate-instances",
				    BAD_CAST temp);
	max_list_num = qci_max_cap.supported_list_max;
	sprintf(temp, "%d", max_list_num);
	xmlNewChild(qci_sg_st_node, NULL,
				    BAD_CAST "supported-list-max",
				    BAD_CAST temp);
	ns = xmlNewNs(qci_sg_st_node, BAD_CAST PSFP_NS, BAD_CAST PSFP_PREFIX);
	xmlSetNs(qci_sg_st_node, ns);
	if (qci_sg_st_node == NULL) {
		rc = EXIT_FAILURE;
		goto out;
	} else {
		max_list_num = qci_max_cap.max_sg_instance;
		rc = get_qci_stream_gates_status(port, qci_sg_st_node,
						max_list_num);
		if (rc != EXIT_SUCCESS)
			goto out;
	}
	qci_fm_st_node = xmlNewChild(node, NULL, BAD_CAST "flow-meters", NULL);
	if (qci_fm_st_node == NULL) {
		rc = EXIT_FAILURE;
		goto out;
	}
	ns = xmlNewNs(qci_fm_st_node, BAD_CAST PSFP_NS, BAD_CAST PSFP_PREFIX);
	xmlSetNs(qci_fm_st_node, ns);

	max_list_num = qci_max_cap.max_fm_instance;
	sprintf(temp, "%d", max_list_num);
	max_list_node = xmlNewChild(qci_fm_st_node, NULL,
				    BAD_CAST "max-stream-gate-instances",
				    BAD_CAST temp);
	if (max_list_node == NULL) {
		rc = EXIT_FAILURE;
		goto out;
	} else {
		max_list_num = qci_max_cap.max_fm_instance;
		rc = get_qci_flow_meters_status(port, qci_fm_st_node,
						max_list_num);
		if (rc != EXIT_SUCCESS)
			goto out;
	}
out:
	genl_tsn_close();
	return rc;
}
