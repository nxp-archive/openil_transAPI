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
#include <errno.h>
#include <xml_node_access.h>

int xml_read_field(xmlNode *node, char *field_name, char *data,
	char *err_msg, char *node_path)
{
	char     *value = NULL;
	int       rc = EXIT_SUCCESS;
	xmlNode  *cur;

	if (!node || !field_name || !data) {
		nc_verb_verbose("null input");
		return -1;
	}
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
			rc = str_to_num(content, NUM_TYPE_U32, ele_val,
					&num, err_msg, node_path);
			if (rc < 0)
				goto out;
		} else if (strcmp(content, "denominator") == 0) {
			rc = xml_read_field(node, "denominator",
					    ele_val, err_msg, node_path);
			if (rc != EXIT_SUCCESS)
				goto out;
			rc = str_to_num(content, NUM_TYPE_U32, ele_val,
					&den, err_msg, node_path);
			if (rc < 0)
				goto out;
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

void str_del_last_key(char *str)
{
	char *char_ptr = str;
	int i;
	int len = strlen(str);

	char_ptr += len - 1;
	if (*char_ptr != ')')
		return;

	for (i = 1; i < len; i++) {
		if (*char_ptr == '(')
			break;
		char_ptr--;
	}
	*char_ptr = 0;
}

/**
 * @brief convert string to number in unsigned long type
 */
int str_to_num(char *node_name, int type, char *str, uint64_t *num,
		char *err_msg, char *node_path)
{
	char *char_ptr;
	char ch;
	int len;
	int base = 0;
	int i;

	char_ptr = str;
	len = strlen(str);
	if ((strncmp(str, "0x", 2) == 0) || (strncmp(str, "0X", 2) == 0)) {
		char_ptr += 2;
		for (i = 2; i < len; i++) {
			ch = *char_ptr;
			if ((ch < '0') || ((ch > '9') && (ch < 'A')) ||
			    ((ch > 'F') && (ch < 'a')) || (ch > 'f'))
				goto err1;

			char_ptr++;
		}
		base = 16;
		goto convert;
	}

	char_ptr = str;
	char_ptr += len - 1;
	ch = *char_ptr;
	if ((ch == 'b') || (ch == 'B')) {
		char_ptr = str;
		for (i = 0; i < len - 1; i++) {
			ch = *char_ptr;
			if ((ch < '0') || (ch > '1'))
				goto err1;

			char_ptr++;
		}
		base = 2;
		goto convert;
	}

	char_ptr = str;
	if (*char_ptr == '0') {
		char_ptr++;
		for (i = 1; i < len; i++) {
			ch = *char_ptr;
			if ((ch < '0') || (ch > '7'))
				goto err1;

			char_ptr++;
		}
		base = 8;
		goto convert;
	}

	char_ptr = str;
	for (i = 0; i < len; i++) {
		ch = *char_ptr;
		if ((ch < '0') || (ch > '9'))
			goto err1;

		char_ptr++;
	}
	base = 10;

convert:
	errno = 0;
	*num = strtoul(str, NULL, base);
	if (errno == ERANGE)
		goto err2;
	// check type limit
	switch (type) {
	case NUM_TYPE_S8:
		if ((*num < -127) || (*num > 127))
			goto err2;
		break;
	case NUM_TYPE_U8:
		if (*num > 255)
			goto err2;
		break;
	case NUM_TYPE_S16:
		if ((*num < -32767) || (*num > 32767))
			goto err2;
		break;
	case NUM_TYPE_U16:
		if (*num > 65535)
			goto err2;
		break;
	case NUM_TYPE_S32:
		if ((*num < -2147483647) || (*num > 2147483647))
			goto err2;
		break;
	case NUM_TYPE_U32:
		if (*num > 4294967295)
			goto err2;
		break;
	case NUM_TYPE_S64:
		if ((*num < -9223372036854775807) ||
		    (*num > 9223372036854775807))
			goto err2;
		break;
	case NUM_TYPE_U64:
		if (*num > 0xFFFFFFFFFFFFFFFF)
			goto err2;
		break;
	default:
		goto err1;
	}
	return 0;
err1:
	sprintf(err_msg, "Invalid '%s' in '%s'", node_name, node_path);
	return -1;
err2:
	sprintf(err_msg, "'%s' in '%s' out of range!", node_name, node_path);
	return -1;
}

xmlNodePtr find_node_in_list(xmlNodePtr lpnode, char *key, xmlNodePtr node)
{
	char *content;
	xmlNodePtr tmp;
	xmlNodePtr keynode;
	char keyval[20];
	char tmpkey[20];

	nc_verb_verbose("%s is called", __func__);
	if (!lpnode || !key || !node)
		return NULL;

	keynode = get_child_node(node, key);
	if (!keynode) {
		nc_verb_verbose("get key node failed");
		return NULL;
	}
	xml_read_field(keynode, key, keyval, NULL, NULL);

	for (tmp = lpnode->children; tmp != NULL; tmp = tmp->next) {
		if (tmp->type != XML_ELEMENT_NODE)
			continue;
		content = (char *)tmp->name;
		if (strcmp(content, (char *)node->name) == 0) {
			keynode = get_child_node(tmp, key);
			if (!keynode) {
				nc_verb_verbose("loop get key node failed");
				return NULL;
			}
			xml_read_field(keynode, key, tmpkey, NULL, NULL);
			if (strcmp(keyval, tmpkey) == 0) {
				return tmp;
			}
		}
	}
	return NULL;
}

void xml_repalce_same_node(xmlNodePtr target, xmlNodePtr src)
{
	xmlNodePtr target_child;
	xmlNodePtr src_child;

	nc_verb_verbose("%s is called", __func__);
	if (!target || !src)
		return;
	for (src_child = src->children; src_child != NULL;
	     src_child = src_child->next) {
		if (src_child->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp((char *)src_child->name, "name") == 0 ||
		    strcmp((char *)src_child->name, "enabled") == 0 ||
		    strcmp((char *)src_child->name, "type") == 0)
			continue;
		target_child =  get_child_node(target, (char *)src_child->name);
		if (target_child) {
			xmlUnlinkNode(target_child);
			xmlFreeNode(target_child);
		}
		xmlAddChild(target, xmlCopyNode(src_child, 1));
	}
}

int update_interfaces(xmlNodePtr base, xmlNodePtr new)
{
	xmlNodePtr if_new;
	xmlNodePtr target_node;

	nc_verb_verbose("%s is called", __func__);
	for (if_new = new->children; if_new != NULL; if_new = if_new->next) {
		if (if_new->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp((char *)(if_new->name), "interface"))
			continue;
		target_node = find_node_in_list(base, "name", if_new);
		if (!target_node)
			xmlAddChild(base, xmlCopyNode(if_new, 1));
		else
			xml_repalce_same_node(target_node, if_new);
	}
	return EXIT_SUCCESS;
}

int update_bridge(xmlNodePtr base, xmlNodePtr new)
{
	xmlNodePtr cp_new;
	xmlNodePtr target_node;

	nc_verb_verbose("%s is called", __func__);
	for (cp_new = new->children; cp_new != NULL; cp_new = cp_new->next) {
		if (cp_new->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp((char *)(cp_new->name), "component"))
			continue;
		target_node = find_node_in_list(base, "name", cp_new);
		if (!target_node)
			xmlAddChild(base, xmlCopyNode(cp_new, 1));
		else
			xml_repalce_same_node(target_node, cp_new);
	}
	return EXIT_SUCCESS;
}

int update_bridges(xmlNodePtr base, xmlNodePtr new)
{
	xmlNodePtr bd_new;
	xmlNodePtr target_node;

	nc_verb_verbose("%s is called", __func__);
	for (bd_new = new->children; bd_new != NULL; bd_new = bd_new->next) {
		if (bd_new->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp((char *)(bd_new->name), "bridge"))
			continue;
		target_node = find_node_in_list(base, "name", bd_new);
		if (!target_node)
			xmlAddChild(base, xmlCopyNode(bd_new, 1));
		else
			update_bridge(target_node, bd_new);
	}
	return EXIT_SUCCESS;
}

void unlink_child(xmlNodePtr parent)
{
	xmlNodePtr child, bak;

	for (child = parent->children; child != NULL;) {
		bak = child->next;
		xmlUnlinkNode(child);
		xmlFree(child);
		child = bak;
	}
}

void strip_def_node_recursive(xmlNodePtr parent)
{
	xmlNodePtr child, tmp;
	char *prop;

	nc_verb_verbose("%s is called", __func__);
	for (child = parent->children; child != NULL;) {
		if (child->type != XML_ELEMENT_NODE) {
			child = child->next;
			continue;
		}

		prop = (char *)xmlGetProp(child, BAD_CAST "default");
		if (prop) {
			tmp = child->next;
			xmlUnlinkNode(child);
			xmlFreeNode(child);
			child = tmp;
			continue;
		}
		if (child->children) {
			strip_def_node_recursive(child);
			if (!child->children) {
				tmp = child->next;
				xmlUnlinkNode(child);
				xmlFreeNode(child);
				child = tmp;
				continue;
			}
		}
		child = child->next;
	}
}

void mac_ul2yangstr(uint64_t mac_ul, char *mac_str)
{
	uint64_t mask = 0xff;
	uint8_t temp;
	int i;
	char chr[8];

	if (!mac_str)
		return;
	memset(mac_str, 0, 20);
	for (i = 5; i >= 0; i--) {
		temp = (uint8_t)(((mask << (8 * i)) & mac_ul) >> (8 * i));
		sprintf(chr, "%02X", temp);
		strcat(mac_str, chr);
		if (i)
			strcat(mac_str, "-");
	}
}

void pri_int2yangstr(int8_t pri, char *str)
{
	if (!str)
		return;

	if (pri == -1)
		sprintf(str, "wildcard");
	else if (pri == 0)
		sprintf(str, "zero");
	else if (pri == 1)
		sprintf(str, "one");
	else if (pri == 2)
		sprintf(str, "two");
	else if (pri == 3)
		sprintf(str, "three");
	else if (pri == 4)
		sprintf(str, "four");
	else if (pri == 5)
		sprintf(str, "five");
	else if (pri == 6)
		sprintf(str, "six");
	else if (pri == 7)
		sprintf(str, "seven");
	else
		sprintf(str, "unknown");
}
