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
#include <cjson/cJSON.h>

cJSON *get_list_item(const cJSON *object, const char *name, int index)
{
	int cnt = 0;
	cJSON *ele;

	if ((object == NULL) || (name == NULL))
		return NULL;

	for (ele = object->child; ele != NULL; ele = ele->next) {
		if (!strcmp(name, ele->string)) {
			if (index == cnt)
				break;
			cnt++;
		}
	}

	if ((ele == NULL) || (ele->string == NULL))
		return NULL;

	return ele;
}

