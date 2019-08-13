/*
 * SPDX-License-Identifier:	(GPL-2.0 OR MIT)
 *
 * Copyright 2019 NXP
 */
#include <cjson/cJSON.h>

#ifndef __JSON_NODE_ACCESS_H__
#define __JSON_NODE_ACCESS_H__

cJSON *get_list_item(const cJSON *object, const char *name, int index);

#endif
