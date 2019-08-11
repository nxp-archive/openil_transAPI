/*
 * SPDX-License-Identifier:	(GPL-2.0 OR MIT)
 *
 * Copyright 2019 NXP
 */
#include <tsn/genl_tsn.h>
#include <linux/tsn.h>
#include <libxml/tree.h>
#include <libnetconf_xml.h>

#ifndef __INTERFACES_H__
#define __INTERFACES_H__

#define IF_NS		"urn:ietf:params:xml:ns:yang:ietf-interfaces"
#define IF_PREFIX	"if"
#define QBV_NS		"urn:ieee:std:802.1Q:yang:ieee802-dot1q-sched"
#define QBV_PREFIX	"sched"
#define QBU_NS		"urn:ieee:std:802.1Q:yang:ieee802-dot1q-preemption"
#define QBU_PREFIX	"preempt"


#define QBV_MASK 0x00000001
#define QBU_MASK 0x00000002
#endif

