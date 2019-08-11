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
#include <libnetconf_xml.h>
#include <pthread.h>
#include "platform.h"

#define GET_SWITCH_PORT_NAME_CMD "ls /sys/bus/pci/devices/0000:00:00.5/net/"
#define GET_ENETC0_PORT_NAME_CMD "ls /sys/bus/pci/devices/0000:00:00.0/net/"
#define GET_ENETC2_PORT_NAME_CMD "ls /sys/bus/pci/devices/0000:00:00.2/net/"
#define GET_ENETC3_PORT_NAME_CMD "ls /sys/bus/pci/devices/0000:00:00.6/net/"
#define INIT_PTP_CMD "devmem 0x1fc0900a0 w 0x00000004"
#define GET_PTP_SECOND_CMD "devmem 0x1fc0900a0"


int enable_timestamp_on_switch(void)
{
	int rc = EXIT_SUCCESS;
	FILE *fp1;
	FILE *fp2;
	char cmd[50];
	char cmd_rst[50];
	unsigned long tmp = 0;

	nc_verb_verbose("%s is called", __func__);
	strcpy(cmd, GET_PTP_SECOND_CMD);
	fp1 = popen(cmd, "r");
	if (fp1) {
		if (fgets(cmd_rst, MAX_PORT_NAME_LEN, fp1) != NULL)
			tmp = strtoul(cmd_rst, NULL, 0);
	} else {
		rc = EXIT_FAILURE;
	}
	if (WEXITSTATUS(pclose(fp1)))
		rc = EXIT_FAILURE;

	if (!(tmp&0x00000004)) {
		nc_verb_verbose("ptp is isn't work");
		memset(cmd, 0, 50);
		strcpy(cmd, INIT_PTP_CMD);
		fp2 = popen(cmd, "r");
		if (WEXITSTATUS(pclose(fp2)))
			rc = EXIT_FAILURE;
	}
	return rc;
}


int get_port_name_list(char *port_name_list, unsigned int type)
{
	FILE *fp;
	int rc = EXIT_SUCCESS;
	int len = 0;
	char cmd_rst[MAX_PORT_NAME_LEN];

	nc_verb_verbose("%s is called", __func__);
	memset(port_name_list, 0, MAX_PORT_NAME_LEN);
	if (type & ENETC_TYPE) {
		fp = popen(GET_ENETC0_PORT_NAME_CMD, "r");
		if (fp) {
			while (fgets(cmd_rst, MAX_PORT_NAME_LEN, fp) != NULL) {
				len = strlen(cmd_rst) - 1;
				if (cmd_rst[len] == '\n') {
					cmd_rst[len] = ' ';
					cmd_rst[len+1] = '\0';
				}
				strcat(port_name_list, cmd_rst);
			}
		} else {
			nc_verb_verbose("enetc0 err");
		}
		if (WEXITSTATUS(pclose(fp))) {
			rc = EXIT_FAILURE;
			goto out;
		}
		fp = popen(GET_ENETC2_PORT_NAME_CMD, "r");
		if (fp) {
			while (fgets(cmd_rst, MAX_PORT_NAME_LEN, fp) != NULL) {
				len = strlen(cmd_rst) - 1;
				if (cmd_rst[len] == '\n') {
					cmd_rst[len] = ' ';
					cmd_rst[len+1] = '\0';
				}
				strcat(port_name_list, cmd_rst);
			}
		} else {
			nc_verb_verbose("enetc2 err");
		}
		if (WEXITSTATUS(pclose(fp))) {
			rc = EXIT_FAILURE;
			goto out;
		}
		fp = popen(GET_ENETC3_PORT_NAME_CMD, "r");
		if (fp) {
			while (fgets(cmd_rst, MAX_PORT_NAME_LEN, fp) != NULL) {
				len = strlen(cmd_rst) - 1;
				if (cmd_rst[len] == '\n') {
					cmd_rst[len] = ' ';
					cmd_rst[len+1] = '\0';
				}
				strcat(port_name_list, cmd_rst);
			}
		} else {
			nc_verb_verbose("enetc3 err");
		}
		if (WEXITSTATUS(pclose(fp))) {
			rc = EXIT_FAILURE;
			goto out;
		}
	}
	if (type & SWITCH_TYPE) {
		nc_verb_verbose("set switch type");
		fp = popen(GET_SWITCH_PORT_NAME_CMD, "r");
		if (fp) {
			while (fgets(cmd_rst, MAX_PORT_NAME_LEN, fp) != NULL) {
				len = strlen(cmd_rst) - 1;
				if (cmd_rst[len] == '\n') {
					cmd_rst[len] = ' ';
					cmd_rst[len+1] = '\0';
				}
				strcat(port_name_list, cmd_rst);
			}
		}
		if (WEXITSTATUS(pclose(fp))) {
			rc = EXIT_FAILURE;
			goto out;
		}
	}
out:
	return rc;
}

