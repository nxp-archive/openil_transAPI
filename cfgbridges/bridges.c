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
	/* Init libxml */
	xmlInitParser();
	bridge_cfg_change_ind = 0;
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
	xmlNewChild(bridge_node, NULL, BAD_CAST "components", BAD_CAST temp);
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

	bridge_cfg_change_ind |= QCI_FMI_MASK;

	return rc;
}

int callback_bridge_stream_gates(__attribute__((unused)) void **data,
		__attribute__((unused)) XMLDIFF_OP op,
		__attribute__((unused)) xmlNodePtr old_node,
		__attribute__((unused)) xmlNodePtr new_node,
		__attribute__((unused)) struct nc_err **error)
{
	int rc = EXIT_SUCCESS;

	bridge_cfg_change_ind |= QCI_SGI_MASK;

	return rc;
}
int callback_bridge_stream_filters(__attribute__((unused)) void **data,
		__attribute__((unused)) XMLDIFF_OP op,
		__attribute__((unused)) xmlNodePtr old_node,
		__attribute__((unused)) xmlNodePtr new_node,
		__attribute__((unused)) struct nc_err **error)
{
	int rc = EXIT_SUCCESS;

	bridge_cfg_change_ind |= QCI_SFI_MASK;

	return rc;
}
int callback_bridge_stream_id(__attribute__((unused)) void **data,
		__attribute__((unused)) XMLDIFF_OP op,
		__attribute__((unused)) xmlNodePtr old_node,
		__attribute__((unused)) xmlNodePtr new_node,
		__attribute__((unused)) struct nc_err **error)
{
	int rc = EXIT_SUCCESS;

	bridge_cfg_change_ind |= CB_MASK;

	return rc;
}
int callback_bridge(__attribute__((unused)) void **data,
		__attribute__((unused)) XMLDIFF_OP op,
		__attribute__((unused)) xmlNodePtr old_node,
		__attribute__((unused)) xmlNodePtr new_node,
		__attribute__((unused)) struct nc_err **error)
{
	int rc = EXIT_SUCCESS;


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
	int disable = 0;
	char init_socket = 0;
	char name[MAX_IF_NAME_LENGTH] = {0};
	char path[MAX_PATH_LENGTH];

	nc_verb_verbose("%s is called", __func__);
	if (op & XMLDIFF_REM) {
		if (!old_node) {
			node = new_node;
			disable = 1;
		} else {
			node = old_node;
		}
		nc_verb_verbose("remove operation");
	} else {
		node = new_node;
		nc_verb_verbose("modify operation");
	}
	/* get component's name */
	name_node = get_child_node(node, "name");
	rc = xml_read_field(name_node, "name", name, NULL, NULL);
	if (rc != EXIT_SUCCESS) {
		sprintf(err_msg, "can not find interface name!");
		goto out;
	}

	sprintf(path, "/bridges/bridge(%s)/component", name);

	/* init socket */
	genl_tsn_init();
	init_socket = 1;

	/* check qci stream filters configuration */
	if (bridge_cfg_change_ind & QCI_SFI_MASK) {
		bridge_cfg_change_ind &= ~QCI_SFI_MASK;
		sub_node = get_child_node(node, "stream-filters");
		strcat(path, "/stream-filters");
		rc = stream_filters_handle(name, sub_node,
					   err_msg, path, disable);
		if (rc != EXIT_SUCCESS)
			goto out;
	}

	/* check qci stream gates configuration */
	if (bridge_cfg_change_ind & QCI_SGI_MASK) {
		bridge_cfg_change_ind &= ~QCI_SGI_MASK;
		sub_node = get_child_node(node, "stream-gates");
		strcat(path, "/stream-gates");
		rc = stream_gates_handle(name, sub_node, err_msg,
					 path, disable);
		if (rc != EXIT_SUCCESS)
			goto out;
	}

	/* check qci flow meters configuration */
	if (bridge_cfg_change_ind & QCI_FMI_MASK) {
		bridge_cfg_change_ind &= ~QCI_FMI_MASK;
		sub_node = get_child_node(node, "flow-meters");
		strcat(path, "/flow-meters");
		rc = flowmeters_handle(name, sub_node, err_msg,
				       path, disable);
		if (rc != EXIT_SUCCESS)
			goto out;
	}

	/* check cb stream filters identification configuration */
	if (bridge_cfg_change_ind & CB_MASK) {
		bridge_cfg_change_ind &= ~CB_MASK;
		sub_node = get_child_node(node, "streams");
		strcat(path, "/streams");
		rc = cbstreamid_handle(name, sub_node, err_msg, path, disable);
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
	.callbacks_count = 76,
	.data = NULL,
	.callbacks = {
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
			.func = callback_bridge_flow_meters},
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

/*
 * Structure transapi_file_callbacks provides mapping between specific files
 * (e.g. configuration file in /etc/) and the callback function executed when
 * the file is modified.
 * The structure is empty by default. Add items, as in example, as you need.
 *
 * Example:
 * int example_callback(const char *filepath,
 *	xmlDocPtr *edit_config, int *exec) {
 *     // do the job with changed file content
 *     // if needed, set edit_config parameter to the edit-config
 *     //data to be applied
 *     // if needed, set exec to 1 to perform consequent transapi callbacks
 *     return 0;
 * }
 *
 * struct transapi_file_callbacks file_clbks = {
 *     .callbacks_count = 1,
 *     .callbacks = {
 *         {.path = "/etc/my_cfg_file", .func = example_callback}
 *     }
 * }
 */
struct transapi_file_callbacks file_clbks = {
	.callbacks_count = 0,
	.callbacks = {
	}
};
