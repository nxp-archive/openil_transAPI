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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <libxml/tree.h>
#include <libnetconf_xml.h>
#include <pthread.h>
#include <semaphore.h>
#include <tsn/genl_tsn.h>
#include <linux/tsn.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include "platform.h"
#include "interfaces.h"
#include "parse_qbv_node.h"
#include "parse_qbu_node.h"
#include "xml_node_access.h"
#include "json_node_access.h"

static int cfg_change_ind;
static XMLDIFF_OP if_qbv_op;
static XMLDIFF_OP if_qbu_op;
static XMLDIFF_OP if_operating;

/* transAPI version which must be compatible with libnetconf */
int transapi_version = 6;

/* Signal to libnetconf that configuration data were modified by any callback.
 * 0 - data not modified
 * 1 - data has been modified
 */
int config_modified;

pthread_mutex_t datastore_mutex;

/*
 * Determines the callbacks order.
 * Set this variable before compilation and DO NOT modify it in runtime.
 * TRANSAPI_CLBCKS_LEAF_TO_ROOT (default)
 * TRANSAPI_CLBCKS_ROOT_TO_LEAF
 */
const TRANSAPI_CLBCKS_ORDER_TYPE callbacks_order = TRANSAPI_CLBCKS_ORDER_DEFAULT;

/* Do not modify or set! This variable is set by libnetconf to announce
 * edit-config's error-option. Feel free to use it to distinguish module
 * behavior for different error-option values.
 * Possible values:
 * NC_EDIT_ERROPT_STOP - Following callback after failure are not executed,
 *                       all successful callbacks executed till
 failure point must be applied to the device.
 * NC_EDIT_ERROPT_CONT - Failed callbacks are skipped, but all callbacks
 *                       needed to apply configuration changes are executed
 * NC_EDIT_ERROPT_ROLLBACK - After failure, following callbacks are not
 *			executed, but previous successful callbacks
 *			are executed again
 *                       with previous configuration data to roll it back.
 */
NC_EDIT_ERROPT_TYPE erropt = NC_EDIT_ERROPT_NOTSET;


/**
 * @brief Initialize plugin after loaded and before any other functions
 *        are called.

 * This function should not apply any configuration data to the controlled
 * device. If no running is returned (it stays *NULL), complete startup
 * configuration is consequently applied via module callbacks. When a running
 * configuration is returned, libnetconf then applies (via module's callbacks)
 * only the startup configuration data that differ from the returned running
 * configuration data.

 * Please note, that copying startup data to the running is performed only
 * after the libnetconf's system-wide close - see nc_close() function
 * documentation for more information.

 * @param[out] running  Current configuration of managed device.

 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int transapi_init(__attribute__((unused)) xmlDocPtr *running)
{
	xmlDocPtr  doc;
	xmlDocPtr  doc_bak;
	xmlNodePtr root;
	xmlNodePtr root_bak;
	xmlNodePtr startup;
	xmlNodePtr ifs_node = NULL;
	FILE *fp;

	nc_verb_verbose("%s is called", __func__);
	/* Init libxml */
	xmlInitParser();
	config_modified = 0;
	cfg_change_ind = 0;
	if_qbv_op = 0;
	if_qbu_op = 0;
	if_operating = 0;
	/* Init pthread mutex on datastore */
	pthread_mutex_init(&datastore_mutex, NULL);
	init_tsn_mutex();

	/* TODO: Attempt to load the staging area (if one exists)
	 * into the initial running config (*running_node).
	 * Do not fail if we can't (it may simply not exist).
	 *
	 * Code currently commented out because the netopeer server
	 * doesn't seem to want to read the XML document in *running
	 * properly (perhaps the format is wrong?).
	 */

	enable_timestamp_on_switch();

	doc_bak = xmlNewDoc(BAD_CAST "1.0");
	root_bak = xmlNewNode(NULL, BAD_CAST "datastores");
	xmlDocSetRootElement(doc_bak, root_bak);
	xmlNewNs(root_bak, BAD_CAST "urn:cesnet:tmc:datastores:file", NULL);

	if (access(IF_DS, F_OK) == EXIT_SUCCESS) {
		doc = xmlReadFile(IF_DS, NULL, 0);
		if (!doc) {
			nc_verb_verbose("read '%s' failed!", IF_DS);
			return EXIT_FAILURE;
		}
		root = xmlDocGetRootElement(doc);
		startup = get_child_node(root, "startup");
		if (!startup) {
			nc_verb_verbose("can't find startup node");
			xmlFreeDoc(doc);
			return EXIT_FAILURE;
		}
		ifs_node = get_child_node(startup, "interfaces");
		if (!ifs_node) {
			ifs_node = xmlNewChild(root_bak, NULL,
					       BAD_CAST "interfaces", NULL);
			xmlNewNs(ifs_node, BAD_CAST IF_NS, BAD_CAST IF_PREFIX);
		} else {
			xmlAddChildList(root_bak, xmlCopyNodeList(ifs_node));
			ifs_node = get_child_node(root_bak, "interfaces");
		}
		xmlFreeDoc(doc);
	} else {
		ifs_node = xmlNewChild(root_bak, NULL,
					  BAD_CAST "interfaces", NULL);
		xmlNewNs(ifs_node, BAD_CAST IF_NS, BAD_CAST IF_PREFIX);
	}
	//xmlNewNs(ifs_node, BAD_CAST QBV_NS, BAD_CAST QBV_PREFIX);
	//xmlNewNs(ifs_node, BAD_CAST QBU_NS, BAD_CAST QBU_PREFIX);
	xmlSaveFormatFileEnc(IF_DS_BAK, doc_bak, "UTF-8", 1);
	xmlFreeDoc(doc_bak);
	//create tsn operation record file
	if (access(TSN_OPR, F_OK) != EXIT_SUCCESS) {
		fp = fopen(TSN_OPR, "w");
		if (fp)
			fclose(fp);
	}
	return EXIT_SUCCESS;
}

/**
 * @brief Free all resources allocated on plugin runtime and prepare
 *        plugin for removal.
 */
void transapi_close(void)
{
	xmlCleanupParser();
	pthread_mutex_destroy(&datastore_mutex);
	destroy_tsn_mutex();
	nc_verb_verbose("%s is called", __func__);
}


/**
 * @brief               Retrieve state data from device and return them
 *                      as XML document
 *
 * @param model         Device data model. libxml2 xmlDocPtr.
 * @param running       Running datastore content. libxml2 xmlDocPtr.
 * @param[out] err      Double pointer to error structure.
 *                      Fill error when some occurs.
 * @return              State data as libxml2 xmlDocPtr or NULL in case
 *                      of error.
 */
xmlDocPtr get_state_data(__attribute__((unused)) xmlDocPtr model,
		__attribute__((unused)) xmlDocPtr running,
		__attribute__((unused)) struct nc_err **error)
{
	xmlDocPtr doc = NULL;
	char port_name_list[MAX_PORT_NAME_LEN];
	char if_name[TOTAL_PORTS][MAX_IF_NAME_LENGTH] = {};
	xmlNodePtr root;
	xmlNsPtr ns;
	xmlNodePtr ifs_node = NULL, if_node = NULL;
	char *port = NULL;
	int i = 0;

	nc_verb_verbose("%s is called", __func__);

	doc = xmlNewDoc(BAD_CAST "1.0");
	root = xmlNewNode(NULL, BAD_CAST "datastores");
	xmlNewNs(root, BAD_CAST "urn:cesnet:tmc:datastores:file", NULL);
	xmlDocSetRootElement(doc, root);
	ifs_node = xmlNewChild(root, NULL, BAD_CAST "interfaces", NULL);
	ns = xmlNewNs(ifs_node, BAD_CAST IF_NS, BAD_CAST IF_PREFIX);
	xmlSetNs(ifs_node, ns);

	get_port_name_list(port_name_list, (ENETC_TYPE | SWITCH_TYPE));
	if (sscanf(port_name_list, "%s %s %s %s %s %s %s %s %s",
	       if_name[0], if_name[1], if_name[2], if_name[3], if_name[4],
	       if_name[5], if_name[6], if_name[7], if_name[8]) < 0)
		goto out;
	for (i = 0; i < TOTAL_PORTS; i++) {
		port = (char *)(if_name + i);
		if_node = xmlNewChild(ifs_node, NULL,
				      BAD_CAST "interface", NULL);
		if (!if_node) {
			*error = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(*error, NC_ERR_PARAM_MSG,
				"Failed to create xml node 'interface'.");
			goto out;
		}
		xmlNewTextChild(if_node, NULL, BAD_CAST "name", BAD_CAST port);
		get_qbv_info(port, if_node, 0);
		get_qbu_info(port, if_node, 0);
	}
out:
	return(doc);
}

/*
 * Mapping prefixes with namespaces.
 * Do NOT modify this structure!
 */
struct ns_pair namespace_mapping[] = {
	{"if", IF_NS},
	{"sched", QBV_NS},
	{"preempt", QBU_NS},
	{NULL, NULL}
};

/*
 * CONFIGURATION callbacks
 * Here follows set of callback functions run every time some change in
 * associated part of running datastore occurs.
 * You can safely modify the bodies of all function as well as add new
 * functions for better lucidity of code.
 */

/**
 * @brief This callback will be run when node in path /nxp:tsn changes
 *
 * @param[in] data	Double pointer to void. Its passed to every
 *			callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy
 *			of node removed.
 * @param[out] error	If callback fails, it can return libnetconf
 *			error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int callback_qbv(__attribute__((unused)) void **data,
		__attribute__((unused)) XMLDIFF_OP op,
		__attribute__((unused)) xmlNodePtr old_node,
		__attribute__((unused)) xmlNodePtr new_node,
		__attribute__((unused)) struct nc_err **error)
{
	int rc = EXIT_SUCCESS;

	//nc_verb_verbose("%s is called", __func__);
	cfg_change_ind |= QBV_MASK;
	if_qbv_op = op;

	return rc;
}

int callback_qbu(__attribute__((unused)) void **data,
		__attribute__((unused)) XMLDIFF_OP op,
		__attribute__((unused)) xmlNodePtr old_node,
		__attribute__((unused)) xmlNodePtr new_node,
		__attribute__((unused)) struct nc_err **error)
{
	int rc = EXIT_SUCCESS;

	//nc_verb_verbose("%s is called", __func__);
	cfg_change_ind |= QBU_MASK;
	if_qbu_op = op;

	return rc;
}

void rem_overrun_node(xmlNodePtr sdu_table)
{
	xmlNodePtr tmp;

	for (tmp = sdu_table->children; tmp != NULL; tmp = tmp->next) {
		if (tmp->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp((char *)(tmp->name), "transmission-overrun") == 0) {
			xmlUnlinkNode(tmp);
			xmlFreeNode(tmp);
		}
	}
}

void rem_dirty_node(xmlNodePtr ifsnode)
{
	xmlNodePtr tmp;
	xmlNodePtr node;
	char *name;
	char *name2;

	for (tmp = ifsnode->children; tmp != NULL; tmp = tmp->next) {
		if (tmp->type != XML_ELEMENT_NODE)
			continue;
		name = (char *)tmp->name;
		if (strcmp(name, "interface") == 0) {
			for (node = tmp->children; node != NULL;
			     node = node->next) {
				if (node->type != XML_ELEMENT_NODE)
					continue;
				name2 = (char *)node->name;
				if (strcmp(name2, "bridge-port") == 0) {
					xmlUnlinkNode(node);
					xmlFreeNode(node);
				}
				if (strcmp(name2, "max-sdu-table") == 0)
					rem_overrun_node(node);
			}
		}
	}
}

int callback_interfaces(__attribute__((unused)) void **data,
		__attribute__((unused)) XMLDIFF_OP op,
		__attribute__((unused)) xmlNodePtr old_node,
		__attribute__((unused)) xmlNodePtr new_node,
		__attribute__((unused)) struct nc_err **error)
{
	int rc = EXIT_SUCCESS;
	xmlDocPtr doc = NULL;
	xmlNodePtr root;
	xmlNodePtr ifs_node;
	xmlNodePtr tmp;

	nc_verb_verbose("%s is called", __func__);
	if_operating = 0;
	pthread_mutex_unlock(&datastore_mutex);

	if ((op & XMLDIFF_REM) == 0) {
		doc = xmlReadFile(IF_DS_BAK, NULL, 0);
		root = xmlDocGetRootElement(doc);
		ifs_node = get_child_node(root, "interfaces");
		if (!ifs_node) {
			nc_verb_verbose("can't find interfaces node");
			xmlFreeDoc(doc);
			return rc;
		}
		tmp = xmlCopyNode(new_node, 1);
		rem_dirty_node(tmp);
		update_interfaces(ifs_node, tmp);
		xmlSaveFile(IF_DS_BAK, doc);
		xmlFreeDoc(doc);
	}
	return rc;
}

int callback_interface(__attribute__((unused)) void **data,
		__attribute__((unused)) XMLDIFF_OP op,
		__attribute__((unused)) xmlNodePtr old_node,
		__attribute__((unused)) xmlNodePtr new_node,
		__attribute__((unused)) struct nc_err **error)
{
	xmlNodePtr name_node = NULL;
	struct std_qbv_conf qbv_conf;
	struct tsn_qbv_entry *qbv_entry = NULL;
	struct std_qbu_conf qbu_conf;
	xmlNodePtr node;
	char err_msg[MAX_ELEMENT_LENGTH];
	int rc = EXIT_SUCCESS;
	int enable = 0;
	char init_socket = 0;
	char ifname[MAX_IF_NAME_LENGTH] = {0};
	char path[MAX_PATH_LENGTH];

	nc_verb_verbose("%s is called", __func__);
	if (!if_operating) {
		pthread_mutex_lock(&datastore_mutex);
		if_operating = 1;
	}
	/* get interface's name */
	node = (op & XMLDIFF_REM)?old_node:new_node;
	name_node = get_child_node(node, "name");
	rc = xml_read_field(name_node, "name", ifname, NULL, NULL);
	if (rc != EXIT_SUCCESS) {
		sprintf(err_msg, "can not find interface name!");
		goto out;
	}

	sprintf(path, "/interfaces/interface(%s)", ifname);

	/* init socket */
	init_tsn_socket();
	init_socket = 1;
	/* check qbv configuration */
	if (cfg_change_ind & QBV_MASK) {
		cfg_change_ind &= ~QBV_MASK;
		if (if_qbv_op & XMLDIFF_REM) {
			goto out;
		} else {
			node = new_node;
			nc_verb_verbose("use new node");
		}
		if (node == NULL) {
			nc_verb_verbose("null node");
			goto out;
		}
		/* applying memory for qbv configuration data */
		qbv_entry = (struct tsn_qbv_entry *)malloc(MAX_ENTRY_SIZE);
		if (qbv_entry == NULL) {
			nc_verb_verbose("malloc space error.\n");
			rc = EXIT_FAILURE;
			goto out;
		}
		/* Init qbv configuration data */
		memset(&qbv_conf, 0, sizeof(struct std_qbv_conf));
		memset(qbv_entry, 0, MAX_ENTRY_SIZE);
		qbv_conf.qbv_conf.admin.control_list = qbv_entry;
		rc = parse_qbv_node(node, &qbv_conf, err_msg, path);
		if (rc != EXIT_SUCCESS) {
			nc_verb_verbose("set err ind");
			goto out;
		}

		/* set new qbv configuration */
		enable = qbv_conf.qbv_conf.gate_enabled;
		rc = tsn_qos_port_qbv_set(ifname, &qbv_conf.qbv_conf, enable);
		free(qbv_entry);

		if (rc < 0) {
			sprintf(err_msg, "set qbv configuration error, %s!",
				strerror(-rc));
			goto out;
		}
	}

	/* check qbu configuration */
	if (cfg_change_ind & QBU_MASK) {
		cfg_change_ind &= ~QBU_MASK;
		if (if_qbu_op & XMLDIFF_REM) {
			goto out;
		} else {
			node = new_node;
			nc_verb_verbose("use new node");
		}
		if (node == NULL) {
			nc_verb_verbose("null node");
			goto out;
		}
		rc = parse_qbu_node(node, &qbu_conf, err_msg, path);
		if (rc != EXIT_SUCCESS)
			goto out;

		/* set new qbu configuration */
		rc = tsn_qbu_set(ifname, qbu_conf.pt_vector);

		if (rc < 0) {
			sprintf(err_msg, "set qbu configuration error, %s!",
				strerror(-rc));
			goto out;
		}
	}
out:
	if (rc != EXIT_SUCCESS) {
		*error = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(*error, NC_ERR_PARAM_MSG, err_msg);
	}
	if (init_socket)
		close_tsn_socket();
	return rc;
}

/*
 * Structure transapi_config_callbacks provide mapping between callback and
 * path in configuration datastore.
 * It is used by libnetconf library to decide which callbacks will be run.
 * DO NOT alter this structure
 */
struct transapi_data_callbacks clbks =  {
	.callbacks_count = 21,
	.data = NULL,
	.callbacks = {
		{.path = "/if:interfaces",
			.func = callback_interfaces},
		{.path = "/if:interfaces/if:interface",
			.func = callback_interface},
		{.path = "/if:interfaces/if:interface/sched:gate-parameters",
			.func = callback_qbv},
		{.path = "/if:interfaces/if:interface/sched:gate-parameters/\
sched:admin-gate-states", .func = callback_qbv},
		{.path = "/if:interfaces/if:interface/sched:gate-parameters/\
sched:admin-control-list-length", .func = callback_qbv},
		{.path = "/if:interfaces/if:interface/sched:gate-parameters/\
sched:admin-control-list", .func = callback_qbv},
		{.path = "/if:interfaces/if:interface/sched:gate-parameters/\
sched:admin-control-list/sched:index", .func = callback_qbv},
		{.path = "/if:interfaces/if:interface/sched:gate-parameters/\
sched:admin-control-list/sched:operation-name", .func = callback_qbv},
		{.path = "/if:interfaces/if:interface/sched:gate-parameters/\
sched:admin-control-list/sched:sgs-params", .func = callback_qbv},
		{.path = "/if:interfaces/if:interface/sched:gate-parameters/\
sched:admin-control-list/sched:sgs-params/sched:gate-states-value",
			 .func = callback_qbv},
		{.path = "/if:interfaces/if:interface/sched:gate-parameters/\
sched:admin-control-list/sched:sgs-params/sched:time-interval-value",
			 .func = callback_qbv},
		{.path = "/if:interfaces/if:interface/sched:gate-parameters/\
sched:admin-cycle-time", .func = callback_qbv},
		{.path = "/if:interfaces/if:interface/sched:gate-parameters/\
sched:admin-cycle-time-extension", .func = callback_qbv},
		{.path = "/if:interfaces/if:interface/sched:gate-parameters/\
sched:admin-base-time", .func = callback_qbv},
		{.path = "/if:interfaces/if:interface/sched:gate-parameters/\
sched:config-change", .func = callback_qbv},
		{.path = "/if:interfaces/if:interface/sched:gate-parameters/\
sched:config-change-time", .func = callback_qbv},
		{.path = "/if:interfaces/if:interface/sched:max-sdu-table",
			.func = callback_qbv},
		{.path = "/if:interfaces/if:interface/\
preempt:frame-preemption-parameters", .func = callback_qbu},
		{.path = "/if:interfaces/if:interface/\
preempt:frame-preemption-parameters/preempt:frame-preemption-status-table",
		.func = callback_qbu},
		{.path = "/if:interfaces/if:interface/\
preempt:frame-preemption-parameters/preempt:frame-preemption-status-table/\
preempt:traffic-class", .func = callback_qbu},
		{.path = "/if:interfaces/if:interface/\
preempt:frame-preemption-parameters/preempt:frame-preemption-status-table/\
preempt:frame-preemption-status", .func = callback_qbu},
	}
};

/*
 * Structure transapi_rpc_callbacks provides mapping between
 * callbacks and RPC messages.
 * It is used by libnetconf library to decide which callbacks
 * will be run when RPC arrives.
 * DO NOT alter this structure
 */
struct transapi_rpc_callbacks rpc_clbks = {
	.callbacks_count = 0,
	.callbacks = {
	}
};

int interfaces_ds_bak_file_change_cb(const char *filepath,
		xmlDocPtr *edit_config, int *exec)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr root;
	xmlNodePtr interfaces;
	xmlNodePtr interfaces2;
	xmlNodePtr child;
	xmlNsPtr ns;

	nc_verb_verbose("%s is called", __func__);
	*exec = 0;
	if (if_operating)
		return EXIT_SUCCESS;

	doc = xmlReadFile(IF_DS_BAK, NULL, 0);
	root = xmlDocGetRootElement(doc);
	interfaces = get_child_node(root, "interfaces");
	if (!interfaces) {
		nc_verb_verbose("get interfaces failed");
		return EXIT_FAILURE;
	}
	child = get_child_node(interfaces, "interface");
	if (!child) {
		nc_verb_verbose("get interface failed");
		return EXIT_FAILURE;
	}
	*edit_config = xmlNewDoc(BAD_CAST "1.0");
	interfaces2 = xmlNewNode(NULL, BAD_CAST "interfaces");
	ns = xmlNewNs(interfaces2, BAD_CAST IF_NS, BAD_CAST IF_PREFIX);
	xmlSetNs(interfaces2, ns);
	ns = xmlNewNs(interfaces2, BAD_CAST QBV_NS, BAD_CAST QBV_PREFIX);
	ns = xmlNewNs(interfaces2, BAD_CAST QBU_NS, BAD_CAST QBU_PREFIX);
	xmlAddChild(interfaces2, xmlCopyNodeList(child));
	xmlDocSetRootElement(*edit_config, interfaces2);
	root = xmlDocGetRootElement(*edit_config);
	if (root) {
		nc_verb_verbose("find edit root");
		xmlNewNs(root,
			 BAD_CAST "urn:ietf:params:xml:ns:netconf:base:1.0",
			 BAD_CAST "ncop");
		xmlSetProp(root, BAD_CAST "ncop:operation", BAD_CAST "replace");
	} else {
		nc_verb_verbose("can't find edit root");
	}
	xmlFreeDoc(doc);
	return EXIT_SUCCESS;
}

int interfaces_tsn_opr_change_cb(const char *filepath,
		xmlDocPtr *edit_config, int *exec)
{
	struct tsn_conf_record record;
	xmlDocPtr doc = NULL;
	xmlNodePtr root;
	xmlNodePtr ifs_node, ifs_new_node;
	xmlNodePtr tmp;
	xmlNsPtr ns;

	nc_verb_verbose("%s is called", __func__);
	if (if_operating) {
		nc_verb_verbose("it is netconf oper");
		return EXIT_SUCCESS;
	}
	if (get_tsn_record(&record) < 0) {
		nc_verb_verbose("get record failed");
		return EXIT_SUCCESS;
	}
	if ((uint32_t)getpid() == record.pid) {
		nc_verb_verbose("it is netconf oper");
		return EXIT_SUCCESS;
	}
	if (record.cmd != TSN_CMD_QBV_SET && record.cmd != TSN_CMD_QBU_SET) {
		nc_verb_verbose("not interfaces' operation");
		return EXIT_SUCCESS;
	}
	usleep(2000);//need to wait for 2ms

	doc = xmlReadFile(IF_DS_BAK, NULL, 0);
	root = xmlDocGetRootElement(doc);
	ifs_node = get_child_node(root, "interfaces");
	if (!ifs_node) {
		nc_verb_verbose("can't find interfaces node");
		xmlFreeDoc(doc);
		return EXIT_SUCCESS;
	}
	ifs_new_node = xmlNewNode(NULL, BAD_CAST "interfaces");
	ns = xmlNewNs(ifs_new_node, BAD_CAST IF_NS, BAD_CAST IF_PREFIX);
	xmlSetNs(ifs_new_node, ns);
	ns = xmlNewNs(ifs_new_node, BAD_CAST QBV_NS, BAD_CAST QBV_PREFIX);
	ns = xmlNewNs(ifs_new_node, BAD_CAST QBU_NS, BAD_CAST QBU_PREFIX);
	tmp = xmlNewChild(ifs_new_node, NULL, BAD_CAST "interface", NULL);
	xmlNewTextChild(tmp, NULL, BAD_CAST "name", BAD_CAST record.portname);
	xmlNewTextChild(tmp, NULL, BAD_CAST "enabled", BAD_CAST "true");

	if (record.cmd == TSN_CMD_QBV_SET)
		get_qbv_info(record.portname, tmp, 1);
	else
		get_qbu_info(record.portname, tmp, 1);
	update_interfaces(ifs_node, xmlCopyNode(ifs_new_node, 1));
	xmlSaveFile(IF_DS_BAK, doc);
	xmlFreeDoc(doc);
	xmlFreeNode(ifs_new_node);
	return EXIT_SUCCESS;
}

struct transapi_file_callbacks file_clbks = {
	.callbacks_count = 2,
	.callbacks = {
		{.path = IF_DS_BAK, .func = interfaces_ds_bak_file_change_cb},
		{.path = TSN_OPR, .func = interfaces_tsn_opr_change_cb},
	}
};
