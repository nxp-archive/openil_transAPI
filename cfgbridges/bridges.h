/*
 * SPDX-License-Identifier:	(GPL-2.0 OR MIT)
 *
 * Copyright 2019 NXP
 */
#include <tsn/genl_tsn.h>
#include <linux/tsn.h>
#include <libxml/tree.h>
#include <libnetconf_xml.h>

#ifndef __BRIDGES_H__
#define __BRIDGES_H__

#define BRIDGE_NS	"urn:ieee:std:802.1Q:yang:ieee802-dot1q-bridge"
#define BRIDGE_PREFIX	"dot1q"
#define IANAIF_NS	"urn:ietf:params:xml:ns:yang:iana-if-type"
#define IANAIF_PREFIX	"ianaift"
#define SFSG_NS "urn:ieee:std:802.1Q:yang:ieee802-dot1q-stream-filters-gates"
#define SFSG_PREFIX	"sfsg"
#define PSFP_NS		"urn:ieee:std:802.1Q:yang:ieee802-dot1q-psfp"
#define PSFP_PREFIX	"psfp"
#define CB_NS		"urn:ieee:std:802.1Q:yang:ieee802-dot1q-stream-id"
#define CB_PREFIX	"stream"

#define QCI_SFI_MASK 0x00000004
#define QCI_SGI_MASK 0x00000008
#define QCI_FMI_MASK 0x00000010
#define CB_MASK  0x00000020
#endif
