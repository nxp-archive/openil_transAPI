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
#include <time.h>
#include "platform.h"
#include "bridges.h"
#include "parse_qci_node.h"
#include "parse_cb_node.h"
#include "xml_node_access.h"

/* transAPI version which must be compatible with libnetconf */
int transapi_version = 6;

/* Signal to libnetconf that configuration data were modified by any callback.
 * 0 - data not modified
 * 1 - data has been modified
 */
int config_modified;

pthread_mutex_t datastore_mutex;

static int bridge_cfg_change_ind;
static XMLDIFF_OP bridge_stream_filters_op;
static XMLDIFF_OP bridge_stream_gates_op;
static XMLDIFF_OP bridge_flow_meters_op;
static XMLDIFF_OP bridge_stream_id_op;

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
 * NC_EDIT_ERROPT_ROLLBACK - After failure, following callbacks
 *			are not executed,
 *                       but previous successful callbacks are executed again
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
	xmlNodePtr bds_node = NULL;
	FILE *fp;

	/* Init libxml */
	xmlInitParser();
	bridge_cfg_change_ind = 0;
	bridge_stream_filters_op = 0;
	bridge_stream_gates_op = 0;
	bridge_flow_meters_op = 0;
	bridge_stream_id_op = 0;
	config_modified = 0;
	/* Init pthread mutex on datastore */
	pthread_mutex_init(&datastore_mutex, NULL);

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

	if (access(BRIDGE_DS, F_OK) == EXIT_SUCCESS) {
		doc = xmlReadFile(BRIDGE_DS, NULL, 0);
		if (!doc) {
			nc_verb_verbose("read '%s' failed!", BRIDGE_DS);
			return EXIT_FAILURE;
		}
		root = xmlDocGetRootElement(doc);
		startup = get_child_node(root, "startup");
		if (!startup) {
			nc_verb_verbose("can't find startup node");
			xmlFreeDoc(doc);
			return EXIT_FAILURE;
		}
		bds_node = get_child_node(startup, "bridges");
		if (!bds_node) {
			bds_node = xmlNewChild(root_bak, NULL,
			BAD_CAST "bridges", NULL);
			xmlNewNs(bds_node, BAD_CAST BRIDGE_NS,
				 BAD_CAST BRIDGE_PREFIX);
		} else {
			xmlAddChildList(root_bak, xmlCopyNodeList(bds_node));
			bds_node = get_child_node(root_bak, "bridges");
		}
		xmlFreeDoc(doc);
	} else {
		bds_node = xmlNewChild(root_bak, NULL,
		BAD_CAST "bridges", NULL);
		xmlNewNs(bds_node, BAD_CAST BRIDGE_NS, BAD_CAST BRIDGE_PREFIX);
	}
	xmlNewNs(bds_node, BAD_CAST SFSG_NS, BAD_CAST SFSG_PREFIX);
	xmlNewNs(bds_node, BAD_CAST PSFP_NS, BAD_CAST PSFP_PREFIX);
	xmlNewNs(bds_node, BAD_CAST CB_NS, BAD_CAST CB_PREFIX);
	xmlSaveFormatFileEnc(BRIDGE_DS_BAK, doc_bak, "UTF-8", 1);
	xmlFreeDoc(doc_bak);
	//create tsn operation record file if not exits
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
}
/*
struct list {
	char * name;
	struct list * next;
};
struct list *create_list(int listnum)
{
	struct list new_list = NULL;
	int index;

	if (!listnum)
		return NULL;
	new_list = malloc(listnum * sizeof(struct list));
	if (!new_list)
		return NULL;

	for (index = 0; index < listnum; index++) {
	}
}
*/
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
	xmlNodePtr bridges_node = NULL;
	xmlNodePtr bridge_node = NULL;
	xmlNodePtr tmp_node = NULL;
	char *port = NULL;
	int i = 0;
	char temp[80] = {0};

	doc = xmlNewDoc(BAD_CAST "1.0");
	root = xmlNewNode(NULL, BAD_CAST "datastores");
	xmlNewNs(root, BAD_CAST "urn:cesnet:tmc:datastores:file", NULL);
	xmlDocSetRootElement(doc, root);
	bridges_node = xmlNewChild(root, NULL, BAD_CAST "bridges", NULL);
	ns = xmlNewNs(bridges_node, BAD_CAST BRIDGE_NS,
		      BAD_CAST BRIDGE_PREFIX);
	xmlSetNs(bridge_node, ns);

	/* add switch ports */
	bridge_node = xmlNewChild(bridges_node, NULL, BAD_CAST "bridge", NULL);
	xmlNewChild(bridge_node, NULL, BAD_CAST "name", BAD_CAST "switch");
	sprintf(temp, "%d", SWITCH_PORT_NUM);
	xmlNewChild(bridge_node, NULL, BAD_CAST "componets", BAD_CAST temp);
	get_port_name_list(port_name_list, SWITCH_TYPE);

	if (sscanf(port_name_list, "%s %s %s %s %s %s",
	       if_name[0], if_name[1], if_name[2], if_name[3], if_name[4],
	       if_name[5]) < 0)
		goto out;
	for (i = 0; i < SWITCH_PORT_NUM; i++) {
		port = (char *)(if_name + i);
		tmp_node = xmlNewChild(bridge_node, NULL,
				       BAD_CAST "compenet", NULL);
		if (!tmp_node) {
			*error = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(*error, NC_ERR_PARAM_MSG,
				"Failed to create xml node 'compenet'.");
			goto out;
		}
		xmlNewTextChild(tmp_node, NULL, BAD_CAST "name",
				BAD_CAST port);
		if (get_qci_status(port, tmp_node)) {
			*error = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(*error, NC_ERR_PARAM_MSG,
				"Failed to create xml node 'qbv'.");
			goto out;
		}
	}
	/* add enetc ports */
	bridge_node = xmlNewChild(bridges_node, NULL, BAD_CAST "bridge", NULL);
	xmlNewChild(bridge_node, NULL, BAD_CAST "name", BAD_CAST "enetc");
	sprintf(temp, "%d", ENETC_PORT_NUM);
	xmlNewChild(bridge_node, NULL, BAD_CAST "component", BAD_CAST temp);
	get_port_name_list(port_name_list, ENETC_TYPE);
	if (sscanf(port_name_list, "%s %s %s",
	       if_name[0], if_name[1], if_name[2]) < 0)
		goto out;
	for (i = 0; i < ENETC_PORT_NUM; i++) {
		port = (char *)(if_name + i);
		tmp_node = xmlNewChild(bridge_node, NULL,
				       BAD_CAST "component", NULL);
		if (!tmp_node) {
			*error = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(*error, NC_ERR_PARAM_MSG,
				"Failed to create xml node 'compenet'.");
			goto out;
		}
		xmlNewTextChild(tmp_node, NULL, BAD_CAST "name",
				BAD_CAST port);
		if (get_qci_status(port, tmp_node)) {
			*error = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(*error, NC_ERR_PARAM_MSG,
				"Failed to create xml node 'qbv'.");
			goto out;
		}
	}
out:
	return doc;
}

/*
 * Mapping prefixes with namespaces.
 * Do NOT modify this structure!
 */
struct ns_pair namespace_mapping[] = {
	{BRIDGE_PREFIX, BRIDGE_NS},
	{PSFP_PREFIX, PSFP_NS},
	{SFSG_PREFIX, SFSG_NS},
	{IANAIF_PREFIX, IANAIF_NS},
	{CB_PREFIX, CB_NS},
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
 * @param[in] data	Double pointer to void. Its passed to every callback.
 *			You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy
 *			of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error
 *			structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int callback_bridge_flow_meters(__attribute__((unused)) void **data,
		__attribute__((unused)) XMLDIFF_OP op,
		__attribute__((unused)) xmlNodePtr old_node,
		__attribute__((unused)) xmlNodePtr new_node,
		__attribute__((unused)) struct nc_err **error)
{
	int rc = EXIT_SUCCESS;

	//nc_verb_verbose("%s is called", __func__);
	bridge_cfg_change_ind |= QCI_FMI_MASK;
	bridge_flow_meters_op = op;

	return rc;
}

int callback_bridge_stream_gates(__attribute__((unused)) void **data,
		__attribute__((unused)) XMLDIFF_OP op,
		__attribute__((unused)) xmlNodePtr old_node,
		__attribute__((unused)) xmlNodePtr new_node,
		__attribute__((unused)) struct nc_err **error)
{
	int rc = EXIT_SUCCESS;

	//nc_verb_verbose("%s is called", __func__);
	bridge_cfg_change_ind |= QCI_SGI_MASK;
	bridge_stream_gates_op = op;

	return rc;
}
int callback_bridge_stream_filters(__attribute__((unused)) void **data,
		__attribute__((unused)) XMLDIFF_OP op,
		__attribute__((unused)) xmlNodePtr old_node,
		__attribute__((unused)) xmlNodePtr new_node,
		__attribute__((unused)) struct nc_err **error)
{
	int rc = EXIT_SUCCESS;

	//nc_verb_verbose("%s is called", __func__);
	bridge_cfg_change_ind |= QCI_SFI_MASK;
	bridge_stream_filters_op = op;

	return rc;
}
int callback_bridge_stream_id(__attribute__((unused)) void **data,
		__attribute__((unused)) XMLDIFF_OP op,
		__attribute__((unused)) xmlNodePtr old_node,
		__attribute__((unused)) xmlNodePtr new_node,
		__attribute__((unused)) struct nc_err **error)
{
	int rc = EXIT_SUCCESS;

	//nc_verb_verbose("%s is called", __func__);
	bridge_cfg_change_ind |= CB_MASK;
	bridge_stream_id_op = op;

	return rc;
}
int callback_bridge(__attribute__((unused)) void **data,
		__attribute__((unused)) XMLDIFF_OP op,
		__attribute__((unused)) xmlNodePtr old_node,
		__attribute__((unused)) xmlNodePtr new_node,
		__attribute__((unused)) struct nc_err **error)
{
	int rc = EXIT_SUCCESS;

	nc_verb_verbose("%s is called", __func__);
	return rc;
}

void clr_bridge_node(xmlNodePtr node)
{
	xmlNodePtr child;
	char *name;

	nc_verb_verbose("%s is called", __func__);
	for (child = node->children; child != NULL; child = child->next) {
		if (child->type != XML_ELEMENT_NODE)
			continue;
		name = (char *)child->name;
		if (strcmp(name, "bridge") == 0)
			strip_def_node_recursive(child);
	}
}

int callback_bridges(__attribute__((unused)) void **data,
		__attribute__((unused)) XMLDIFF_OP op,
		__attribute__((unused)) xmlNodePtr old_node,
		__attribute__((unused)) xmlNodePtr new_node,
		__attribute__((unused)) struct nc_err **error)
{
	int rc = EXIT_SUCCESS;
	xmlDocPtr doc = NULL;
	xmlNodePtr root;
	xmlNodePtr bds_node;
	xmlNodePtr tmp;

	nc_verb_verbose("%s is called", __func__);

	if ((op & XMLDIFF_REM) == 0) {
		nc_verb_verbose("Remove operation");
		doc = xmlReadFile(BRIDGE_DS_BAK, NULL, 0);
		root = xmlDocGetRootElement(doc);
		bds_node = get_child_node(root, "bridges");
		if (!bds_node) {
			nc_verb_verbose("can't find bridges node");
			xmlFreeDoc(doc);
			return rc;
		}
		tmp = xmlCopyNode(new_node, 1);
		clr_bridge_node(tmp);
		nc_verb_verbose("clr bridges node end");
		update_bridges(bds_node, tmp);
		xmlSaveFile(BRIDGE_DS_BAK, doc);
		xmlFreeDoc(doc);
	}
	return rc;
}

int callback_bridge_component(__attribute__((unused)) void **data,
		__attribute__((unused)) XMLDIFF_OP op,
		__attribute__((unused)) xmlNodePtr old_node,
		__attribute__((unused)) xmlNodePtr new_node,
		__attribute__((unused)) struct nc_err **error)
{
	xmlNodePtr node = NULL;
	xmlNodePtr sub_node = NULL;
	xmlNodePtr name_node = NULL;
	int rc = EXIT_SUCCESS;
	char err_msg[MAX_ELEMENT_LENGTH];
	char init_socket = 0;
	char name[MAX_IF_NAME_LENGTH] = {0};
	char path[MAX_PATH_LENGTH];

	nc_verb_verbose("%s is called", __func__);
	/* get component's name */
	node = (op & XMLDIFF_REM)?old_node:new_node;
	name_node = get_child_node(node, "name");
	rc = xml_read_field(name_node, "name", name, NULL, NULL);
	if (rc != EXIT_SUCCESS) {
		sprintf(err_msg, "can not find bridge name!");
		goto out;
	}

	sprintf(path, "/bridges/bridge(%s)/component", name);

	/* init socket */
	genl_tsn_init();
	init_socket = 1;

	/* check qci stream filters configuration */
	if (bridge_cfg_change_ind & QCI_SFI_MASK) {
		bridge_cfg_change_ind &= ~QCI_SFI_MASK;
		if (bridge_stream_filters_op & XMLDIFF_REM) {
			goto out;
		} else {
			node = new_node;
			nc_verb_verbose("use new node");
		}
		sub_node = get_child_node(node, "stream-filters");
		if (sub_node == NULL) {
			rc = EXIT_FAILURE;
			sprintf(err_msg, "can't find 'stream-filters' node");
			goto out;
		}
		strcat(path, "/stream-filters");
		rc = stream_filters_handle(name, sub_node, err_msg, path);
		if (rc != EXIT_SUCCESS)
			goto out;
	}

	/* check qci stream gates configuration */
	if (bridge_cfg_change_ind & QCI_SGI_MASK) {
		bridge_cfg_change_ind &= ~QCI_SGI_MASK;
		if (bridge_stream_gates_op & XMLDIFF_REM) {
			goto out;
		} else {
			node = new_node;
			nc_verb_verbose("use new node");
		}
		sub_node = get_child_node(node, "stream-gates");
		if (sub_node == NULL) {
			rc = EXIT_FAILURE;
			sprintf(err_msg, "can't find 'stream-gates' node");
			goto out;
		}
		strcat(path, "/stream-gates");
		rc = stream_gates_handle(name, sub_node, err_msg, path);
		if (rc != EXIT_SUCCESS)
			goto out;
	}

	/* check qci flow meters configuration */
	if (bridge_cfg_change_ind & QCI_FMI_MASK) {
		bridge_cfg_change_ind &= ~QCI_FMI_MASK;
		if (bridge_flow_meters_op & XMLDIFF_REM) {
			goto out;
		} else {
			node = new_node;
			nc_verb_verbose("use new node");
		}
		sub_node = get_child_node(node, "flow-meters");
		if (sub_node == NULL) {
			rc = EXIT_FAILURE;
			sprintf(err_msg, "can't find 'flow-meters' node");
			goto out;
		}
		strcat(path, "/flow-meters");
		rc = flowmeters_handle(name, sub_node, err_msg, path);
		if (rc != EXIT_SUCCESS)
			goto out;
	}

	/* check cb stream filters identification configuration */
	if (bridge_cfg_change_ind & CB_MASK) {
		bridge_cfg_change_ind &= ~CB_MASK;
		if (bridge_stream_id_op & XMLDIFF_REM) {
			goto out;
		} else {
			node = new_node;
			nc_verb_verbose("use new node");
		}
		sub_node = get_child_node(node, "streams");
		if (sub_node == NULL) {
			rc = EXIT_FAILURE;
			sprintf(err_msg, "can't find 'streams' node");
			goto out;
		}
		strcat(path, "/streams");
		rc = cbstreamid_handle(name, sub_node, err_msg, path);
		if (rc != EXIT_SUCCESS)
			goto out;
	}
out:
	if (rc != EXIT_SUCCESS) {
		*error = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(*error, NC_ERR_PARAM_MSG, err_msg);
	}
	if (init_socket)
		genl_tsn_close();
	return rc;
}

/*
 * Structure transapi_config_callbacks provide mapping between callback and
 * path in configuration datastore.
 * It is used by libnetconf library to decide which callbacks will be run.
 * DO NOT alter this structure
 */
struct transapi_data_callbacks clbks =  {
	.callbacks_count = 77,
	.data = NULL,
	.callbacks = {
		{.path = "/dot1q:bridges", .func = callback_bridges},
		{.path = "/dot1q:bridges/dot1q:bridge",
			.func = callback_bridge},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component",
			.func = callback_bridge_component},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-filters", .func = callback_bridge_stream_filters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-filters/sfsg:stream-filter-instance-table",
			.func = callback_bridge_stream_filters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-filters/sfsg:stream-filter-instance-table/sfsg:stream-filter-instance-id", .func = callback_bridge_stream_filters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-filters/sfsg:stream-filter-instance-table/sfsg:wildcard",
			.func = callback_bridge_stream_filters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-filters/sfsg:stream-filter-instance-table/sfsg:stream-handle",
			.func = callback_bridge_stream_filters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-filters/sfsg:stream-filter-instance-table/sfsg:priority-spec",
			.func = callback_bridge_stream_filters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-filters/sfsg:stream-filter-instance-table/sfsg:stream-gate-ref",
			.func = callback_bridge_stream_filters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-filters/sfsg:stream-filter-instance-table/sfsg:filter-specification-list",
			.func = callback_bridge_stream_filters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-filters/sfsg:stream-filter-instance-table/sfsg:filter-specification-list/sfsg:index",
			.func = callback_bridge_stream_filters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-filters/sfsg:stream-filter-instance-table/sfsg:filter-specification-list/sfsg:maximum-sdu-size",
			.func = callback_bridge_stream_filters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-filters/sfsg:stream-filter-instance-table/sfsg:filter-specification-list/sfsg:stream-blocked-due-to-oversize-frame-enabled",
			.func = callback_bridge_stream_filters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-gates", .func = callback_bridge_stream_gates},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-gates/sfsg:stream-gate-instance-table",
			.func = callback_bridge_stream_gates},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-gates/sfsg:stream-gate-instance-table/sfsg:stream-gate-instance-id", .func = callback_bridge_stream_gates},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-gates/sfsg:stream-gate-instance-table/sfsg:gate-enable",
			.func = callback_bridge_stream_gates},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-gates/sfsg:stream-gate-instance-table/sfsg:admin-gate-states/",
			.func = callback_bridge_stream_gates},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-gates/sfsg:stream-gate-instance-table/sfsg:admin-ipv/",
			.func = callback_bridge_stream_gates},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-gates/sfsg:stream-gate-instance-table/psfp:admin-control-list-length",
			.func = callback_bridge_stream_gates},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-gates/sfsg:stream-gate-instance-table/psfp:admin-control-list",
			.func = callback_bridge_stream_gates},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-gates/sfsg:stream-gate-instance-table/psfp:admin-control-list/psfp:index",
			.func = callback_bridge_stream_gates},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-gates/sfsg:stream-gate-instance-table/psfp:admin-control-list/psfp:operation-name",
			.func = callback_bridge_stream_gates},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-gates/sfsg:stream-gate-instance-table/psfp:admin-control-list/psfp:parameters",
			.func = callback_bridge_stream_gates},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-gates/sfsg:stream-gate-instance-table/psfp:admin-control-list/psfp:parameters/psfp:gate-state-value", .func = callback_bridge_stream_gates},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-gates/sfsg:stream-gate-instance-table/psfp:admin-control-list/psfp:parameters/psfp:ipv-value",
			.func = callback_bridge_stream_gates},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-gates/sfsg:stream-gate-instance-table/psfp:admin-control-list/psfp:parameters/psfp:time-interval-value",
			.func = callback_bridge_stream_gates},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-gates/sfsg:stream-gate-instance-table/psfp:admin-control-list/psfp:parameters/psfp:interval-octet-max", .func = callback_bridge_stream_gates},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/psfp:flow-meters", .func = callback_bridge_flow_meters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/sfsg:stream-filters/sfsg:stream-filter-instance-table/sfsg:filter-specification-list/psfp:flow-meter-ref",
			.func = callback_bridge_stream_filters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/psfp:flow-meters/psfp:flow-meter-instance-table",
			.func = callback_bridge_flow_meters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/psfp:flow-meters/psfp:flow-meter-instance-table/psfp:flow-meter-instance-id",
			.func = callback_bridge_flow_meters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/psfp:flow-meters/psfp:flow-meter-instance-table/psfp:committed-information-rates", .func = callback_bridge_flow_meters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/psfp:flow-meters/psfp:flow-meter-instance-table/psfp:committed-burst-size",
			.func = callback_bridge_flow_meters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/psfp:flow-meters/psfp:flow-meter-instance-table/psfp:excess-information-rate",
			.func = callback_bridge_flow_meters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/psfp:flow-meters/psfp:flow-meter-instance-table/psfp:excess-burst-size",
			.func = callback_bridge_flow_meters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/psfp:flow-meters/psfp:flow-meter-instance-table/psfp:coupling-flag",
			.func = callback_bridge_flow_meters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/psfp:flow-meters/psfp:flow-meter-instance-table/psfp:color-mode",
			.func = callback_bridge_flow_meters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/psfp:flow-meters/psfp:flow-meter-instance-table/psfp:drop-on-yellow",
			.func = callback_bridge_flow_meters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/psfp:flow-meters/psfp:flow-meter-instance-table/psfp:mark-all-frames-red-enable", .func = callback_bridge_flow_meters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/psfp:flow-meters/psfp:flow-meter-instance-table/psfp:mark-all-frames-red",
			.func = callback_bridge_flow_meters},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:index",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:stream-handle",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:in-facing-output-port-list",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:out-facing-output-port-list",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:in-facing-input-port-list",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:out-facing-input-port-list",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:identification-type",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:lan-path-id",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:null-stream-identification-params/stream:dest-address",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:null-stream-identification-params/stream:vlan-tagged",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:null-stream-identification-params/stream:vlan-id",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:source-mac-and-vlan-identification-params/stream:source-address",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:source-mac-and-vlan-identification-params/stream:vlan-tagged",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:source-mac-and-vlan-identification-params/stream:vlan-id",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:dest-mac-and-vlan-identification-params/stream:down-dest-address",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:dest-mac-and-vlan-identification-params/stream:down-vlan-tagged",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:dest-mac-and-vlan-identification-params/stream:down-vlan-id",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:dest-mac-and-vlan-identification-params/stream:down-priority",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:dest-mac-and-vlan-identification-params/stream:up-dest-address",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:dest-mac-and-vlan-identification-params/stream:up-vlan-id",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:dest-mac-and-vlan-identification-params/stream:up-priority",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:ip-octuple-stream-identification-params/stream:vlan-id",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:ip-octuple-stream-identification-params/stream:dest-address",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:ip-octuple-stream-identification-params/stream:down-vlan-tagged",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:ip-octuple-stream-identification-params/stream:source-ip-address/stream:ip-version",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:ip-octuple-stream-identification-params/stream:source-ip-address/stream:ip-address",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:ip-octuple-stream-identification-params/stream:dest-ip-address/stream:ip-version",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:ip-octuple-stream-identification-params/stream:dest-ip-address/stream:ip-address",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:ip-octuple-stream-identification-params/stream:dscp",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:ip-octuple-stream-identification-params/stream:next-protocol",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:ip-octuple-stream-identification-params/stream:source-port",
			.func = callback_bridge_stream_id},
		{.path = "/dot1q:bridges/dot1q:bridge/dot1q:component/stream:streams/stream:stream-identity-table/stream:parameters/stream:ip-octuple-stream-identification-params/stream:dest-port",
			.func = callback_bridge_stream_id},
	}
};


/*
 * Structure transapi_rpc_callbacks provides mapping
 * between callbacks and RPC messages.
 * It is used by libnetconf library to decide which
 * callbacks will be run when RPC arrives.
 * DO NOT alter this structure
 */
struct transapi_rpc_callbacks rpc_clbks = {
	.callbacks_count = 0,
	.callbacks = {}
};

int bridges_ds_bak_file_change_cb(const char *filepath,
		xmlDocPtr *edit_config, int *exec)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr root;
	xmlNodePtr bridges;
	xmlNodePtr bridges2;
	xmlNodePtr child;
	xmlNsPtr ns;

	nc_verb_verbose("%s is called", __func__);
	*exec = 0;

	doc = xmlReadFile(BRIDGE_DS_BAK, NULL, 0);
	root = xmlDocGetRootElement(doc);
	bridges = get_child_node(root, "bridges");
	if (!bridges) {
		nc_verb_verbose("get bridges failed");
		return EXIT_FAILURE;
	}
	child = get_child_node(bridges, "bridge");
	if (!child) {
		nc_verb_verbose("get bridge failed");
		return EXIT_FAILURE;
	}
	*edit_config = xmlNewDoc(BAD_CAST "1.0");
	bridges2 = xmlNewNode(NULL, BAD_CAST "bridges");
	ns = xmlNewNs(bridges2, BAD_CAST BRIDGE_NS, BAD_CAST BRIDGE_PREFIX);
	xmlSetNs(bridges2, ns);
	ns = xmlNewNs(bridges2, BAD_CAST SFSG_NS, BAD_CAST SFSG_PREFIX);
	ns = xmlNewNs(bridges2, BAD_CAST PSFP_NS, BAD_CAST PSFP_PREFIX);
	xmlAddChild(bridges2, xmlCopyNodeList(child));
	xmlDocSetRootElement(*edit_config, bridges2);
	xmlSaveFormatFileEnc("/tmp/edit-config.xml", *edit_config, "UTF-8", 1);
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

int bridges_tsn_opr_change_cb(const char *filepath,
		xmlDocPtr *edit_config, int *exec)
{
	struct tsn_conf_record record;
	xmlDocPtr doc = NULL;
	xmlNodePtr root;
	xmlNodePtr bds_node, bds_new_node;
	xmlNodePtr tmp, component;
	xmlNsPtr ns;

	nc_verb_verbose("%s is called", __func__);
	if (get_tsn_record(&record) < 0) {
		nc_verb_verbose("get record failed");
		return EXIT_SUCCESS;
	}
	if ((uint32_t)getpid() == record.pid) {
		nc_verb_verbose("it is netconf oper");
		return EXIT_SUCCESS;
	}
	if (record.cmd != TSN_CMD_CB_STREAMID_SET &&
	    record.cmd != TSN_CMD_QCI_SFI_SET &&
	    record.cmd != TSN_CMD_QCI_SGI_SET &&
	    record.cmd != TSN_CMD_QCI_FMI_SET) {
		nc_verb_verbose("not bridges' operation");
		return EXIT_SUCCESS;
	}
	usleep(2000);//need to wait for 2ms

	doc = xmlReadFile(BRIDGE_DS_BAK, NULL, 0);
	root = xmlDocGetRootElement(doc);
	bds_node = get_child_node(root, "bridges");
	if (!bds_node) {
		nc_verb_verbose("can't find bridges node");
		xmlFreeDoc(doc);
		return EXIT_SUCCESS;
	}
	bds_new_node = xmlNewNode(NULL, BAD_CAST "bridges");
	ns = xmlNewNs(bds_new_node, BAD_CAST BRIDGE_NS, BAD_CAST BRIDGE_PREFIX);
	xmlSetNs(bds_new_node, ns);
	ns = xmlNewNs(bds_new_node, BAD_CAST SFSG_NS, BAD_CAST SFSG_PREFIX);
	ns = xmlNewNs(bds_new_node, BAD_CAST PSFP_NS, BAD_CAST PSFP_PREFIX);
	ns = xmlNewNs(bds_new_node, BAD_CAST CB_NS, BAD_CAST CB_PREFIX);

	tmp = xmlNewChild(bds_new_node, NULL, BAD_CAST "bridge", NULL);
	if (strncmp(record.portname, "eno", 3) == 0)
		xmlNewTextChild(tmp, NULL, BAD_CAST "name", BAD_CAST "enetc");
	else if (strncmp(record.portname, "swp", 3) == 0)
		xmlNewTextChild(tmp, NULL, BAD_CAST "name", BAD_CAST "switch");
	else
		xmlNewTextChild(tmp, NULL, BAD_CAST "name", BAD_CAST "unknown");
	component = xmlNewChild(tmp, NULL, BAD_CAST "component", NULL);
	xmlNewTextChild(component, NULL, BAD_CAST "name",
			BAD_CAST record.portname);

	switch (record.cmd) {
	case TSN_CMD_CB_STREAMID_SET:
		get_cb_info(record.portname, component, 1, record.para);
		break;
	case TSN_CMD_QCI_SFI_SET:
		get_sfi_config(record.portname, component, 1, record.para);
		break;
	case TSN_CMD_QCI_SGI_SET:
		get_sgi_config(record.portname, component, 1, record.para);
		break;
	case TSN_CMD_QCI_FMI_SET:
		get_fmi_config(record.portname, component, 1, record.para);
		break;
	default:
		break;
	}
	update_bridges(bds_node, xmlCopyNode(bds_new_node, 1));
	xmlSaveFile(BRIDGE_DS_BAK, doc);
	xmlFreeDoc(doc);
	xmlFreeNode(bds_new_node);
	return EXIT_SUCCESS;
}

struct transapi_file_callbacks file_clbks = {
	.callbacks_count = 2,
	.callbacks = {
		{.path = BRIDGE_DS_BAK, .func = bridges_ds_bak_file_change_cb},
		{.path = TSN_OPR, .func = bridges_tsn_opr_change_cb},
	}
};
