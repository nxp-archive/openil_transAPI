/*
 * SPDX-License-Identifier:	(GPL-2.0 OR MIT)
 *
 * Copyright 2019 NXP
 */
#ifndef __PLATFORM_H__
#define __PLATFORM_H__

#include <stdint.h>

#define LS1028ARDB

#ifdef LS1028ARDB

#define ENETC_PORT_NUM 3
#define SWITCH_PORT_NUM 6
#define TOTAL_PORTS ((ENETC_PORT_NUM)+(SWITCH_PORT_NUM))
#define MAX_ELEMENT_LENGTH 100
#define MAX_IF_NAME_LENGTH 20
#define MAX_PORT_NAME_LEN ((TOTAL_PORTS) * (MAX_IF_NAME_LENGTH))
#define MAX_PATH_LENGTH 300

#define SWITCH_TYPE	1
#define ENETC_TYPE	2

#define CONF_FOLDER        "/usr/local/etc/netopeer/tsn"
#define BRIDGE_DS_PATH "/usr/local/etc/netopeer/yang-tsn/bridges/datastore.xml"
#define TEMPXML            "/tmp/tsn-states.xml"
#define TSNTOOL_PORT_ST_FILE "/tmp/tsntool.json"

#endif
struct ieee_cycle_time {
	uint32_t numerator;
	uint32_t denominator;
};

struct ieee_ptp_time {
	uint64_t seconds;
	uint64_t nano_seconds;
};

int enable_timestamp_on_switch(void);
int get_port_name_list(char *port_name_list, unsigned int type);
void init_tsn_mutex(void);
void destroy_tsn_mutex(void);
void init_tsn_socket(void);
void close_tsn_socket(void);
#endif
