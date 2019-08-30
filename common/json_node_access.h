/*
 * SPDX-License-Identifier:	(GPL-2.0 OR MIT)
 *
 * Copyright 2019 NXP
 */
#include <cjson/cJSON.h>

#ifndef __JSON_NODE_ACCESS_H__
#define __JSON_NODE_ACCESS_H__

cJSON *get_list_item(const cJSON *object, const char *name, int index);
void create_op_record(char *ifname, char *path, int tsn, int parameter);
cJSON *open_json_safe(char *file, char *mode);
int is_netconf_op(char *tsn_opr, char *netcof_opr);
int get_opr_info(char *file, char *port_name, int *type, int *parameter);
#endif
