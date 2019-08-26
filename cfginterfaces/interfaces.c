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
#include <errno.h>
#include "platform.h"
#include "interfaces.h"
#include "parse_qbv_node.h"
#include "parse_qbu_node.h"
#include "xml_node_access.h"

static int cfg_change_ind;
static XMLDIFF_OP if_qbv_op;
static XMLDIFF_OP if_qbu_op;

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
	/* Init libxml */
	xmlInitParser();
	config_modified = 0;
	cfg_change_ind = 0;
	if_qbv_op = 0;
	if_qbu_op = 0;
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

	nc_verb_verbose("%s is called", __func__);
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
	xmlNodePtr qbv_node = NULL;
	char *port = NULL;
	int i = 0;

	nc_verb_verbose("%s is called", __func__);

	doc = xmlNewDoc(BAD_CAST "1.0");
	root = xmlNewNode(NULL, BAD_CAST "datastores");
	xmlNewNs(root, BAD_CAST "urn:cesnet:tmc:datastores:file", NULL);
	xmlDocSetRootElement(doc, root);
	ifs_node = xmlNewChild(root, NULL, BAD_CAST "interfaces", NULL);
	ns = xmlNewNs(ifs_node, BAD_CAST IF_NS, BAD_CAST IF_PREFIX);
	xmlSetNs(if_node, ns);

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
		qbv_node = xmlNewChild(if_node, NULL,
				       BAD_CAST "gate-parameters",
				       BAD_CAST NULL);
		ns = xmlNewNs(qbv_node, BAD_CAST QBV_NS, BAD_CAST QBV_PREFIX);
		xmlSetNs(qbv_node, ns);
		if (!qbv_node) {
			*error = nc_err_new(NC_ERR_OP_FAILED);
			nc_err_set(*error, NC_ERR_PARAM_MSG,
				"Failed to create xml node 'qbv'.");
			goto out;
		}
		get_qbv_status(port, if_node);
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
	int disable = 0;
	int enable = 0;
	char init_socket = 0;
	char ifname[MAX_IF_NAME_LENGTH] = {0};
	char path[MAX_PATH_LENGTH];

	nc_verb_verbose("%s is called", __func__);
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
	genl_tsn_init();
	init_socket = 1;
	/* check qbv configuration */
	if (cfg_change_ind & QBV_MASK) {
		cfg_change_ind &= ~QBV_MASK;
		if (if_qbv_op & XMLDIFF_REM) {
			if (!old_node) {
				sprintf(err_msg, "trying to remove a Nonexistent Qbv node");
				rc = EXIT_FAILURE;
				goto out;
			}
			node = old_node;
			disable = 1;
			nc_verb_verbose("use old node");
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
		enable = disable?0:qbv_conf.qbv_conf.gate_enabled;
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
			if (!old_node) {
				sprintf(err_msg, "trying to remove a Nonexistent Qbu node");
				rc = EXIT_FAILURE;
				goto out;
			}
			node = old_node;
			disable = 1;
			nc_verb_verbose("use old node");
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
		if (disable)
			qbu_conf.pt_vector = 0;
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
	.callbacks_count = 20,
	.data = NULL,
	.callbacks = {
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
 *     // if needed, set edit_config parameter to the edit-config data
 *     //to be applied
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


