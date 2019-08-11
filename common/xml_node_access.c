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
