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
#include <platform.h>

int xml_read_field(xmlNode *node, char *field_name, char *data,
	char *err_msg, char *node_path)
{
	char     *value = NULL;
	int       rc = EXIT_SUCCESS;
	xmlNode  *cur;

	for (cur = node; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, (const xmlChar *)field_name) != 0)
			continue;
		value = (char *)xmlNodeListGetString(cur->doc,
						     cur->xmlChildrenNode, 1);
	}
	if (value == NULL) {
		rc = EXIT_FAILURE;
		if ((err_msg != NULL) && (node_path != NULL))
			sprintf(err_msg, "Failed to parse '%s' in '%s'!",
				field_name, node_path);
		goto out;
	} else {
		snprintf(data, MAX_ELEMENT_LENGTH, value);
	}
out:
	xmlFree(value);
	return rc;
}


xmlNodePtr get_child_node(xmlNodePtr parent_node, const char *child_node_name)
{
	xmlNodePtr node = NULL;

	if (parent_node->type != XML_ELEMENT_NODE) {
		nc_verb_error("Root node must be of element type!");
		goto out;
	}
	for (node = parent_node->children; node != NULL; node = node->next) {
		if (!strcmp((char *)node->name, child_node_name))
			return node;
	}
out:
	return NULL;
}

int get_cycle_time(xmlNode *node, uint32_t *cycle_time,
	char *err_msg, char *node_path)
{
	int rc = EXIT_SUCCESS;
	char *content;
	char ele_val[MAX_ELEMENT_LENGTH];
	uint64_t num = 0;
	uint64_t den = 1;

	nc_verb_verbose("%s is called", __func__);

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_ELEMENT_NODE)
			continue;

		content = (char *)node->name;
		if (strcmp(content, "numerator") == 0) {
			rc = xml_read_field(node, "numerator",
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;
			num = strtoul(ele_val, NULL, 0);
		} else if (strcmp(content, "denominator") == 0) {
			rc = xml_read_field(node, "denominator",
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;
			den = strtoul(ele_val, NULL, 0);
			if (!den) {
				nc_verb_verbose("Invalid '%s' in '%s'",
						content, node_path);
			}
		}
	}
	*cycle_time = (uint32_t)((num * 1000000000)/den);
out:
	return rc;
}
/**
 * @brief Create a xmldoc with root node and namespace
 *        return the root node pointer.
 */

xmlNodePtr create_root_in_doc(xmlDocPtr doc, char *rootname, char *ns)
{
	xmlNodePtr root;

	if (!rootname || !ns)
		return NULL;

	doc = xmlNewDoc(BAD_CAST "1.0");
	root = xmlNewNode(NULL, BAD_CAST rootname);
	xmlNewNs(root, BAD_CAST ns, NULL);
	xmlDocSetRootElement(doc, root);
	return root;
}
xmlNodePtr create_root_in_doc_no_ns(xmlDocPtr doc, char *rootname)
{
	xmlNodePtr root;

	if (!rootname)
		return NULL;

	doc = xmlNewDoc(BAD_CAST "1.0");
	root = xmlNewNode(NULL, BAD_CAST rootname);
	xmlDocSetRootElement(doc, root);
	return root;
}

/**
 * @brief free the xmlDocPtr memory
 */
void free_doc_mem(xmlDocPtr doc)
{
	if (doc)
		xmlFreeDoc(doc);
}

void prt_err_bool(char *err_msg, char *name, char *path)
{
	sprintf(err_msg,
		"the value of '%s' in '%s' must be 'true' or 'false'!",
		name, path);
}
