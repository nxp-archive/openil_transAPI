# transAPI
## Introduction

The purpose of this project is to implement the transAPI part of [netopeer](https://github.com/CESNET/netopeer). transAPI plays the role of parsing and applying configuration and getting device status.

In this project, we use tsn related models from [yang](https://github.com/YangModels/yang), like [ieee802-dot1q-preemption.yang](https://github.com/YangModels/yang/tree/master/standard/ieee/draft/802.1/Qcw), as our models' source to creat netopeer transAPI. The transAPI together with netopeer server in the device to can implement tsn configuration based on NETCONF protocol.

![project overview](./images/yang-models-plus.png)

## yang models

Project mainly uses following models:
  - [ietf-interfaces@2014-05-08.yang](https://github.com/YangModels/yang/blob/master/standard/ietf/RFC/ietf-interfaces%402014-05-08.yang)
  - [ieee802-dot1q-preemption.yang](https://github.com/YangModels/yang/blob/master/standard/ieee/draft/802.1/Qcw/ieee802-dot1q-preemption.yang)
  - [ieee802-dot1q-sched.yang](https://github.com/YangModels/yang/blob/master/standard/ieee/draft/802.1/Qcw/ieee802-dot1q-sched.yang)
  - [ieee802-dot1q-bridge.yang](https://github.com/YangModels/yang/blob/master/standard/ieee/published/802.1/ieee802-dot1q-bridge.yang)
  - [ieee802-dot1q-stream-filters-gates.yang](https://github.com/YangModels/yang/blob/master/standard/ieee/draft/802.1/Qcr/ieee802-dot1q-stream-filters-gates.yang)
  - [ieee802-dot1q-psfp.yang](https://github.com/YangModels/yang/blob/master/standard/ieee/draft/802.1/Qcw/ieee802-dot1q-psfp.yang)

Where, **ietf-interfaces@2014-05-08.yang** and **ieee802-dot1q-bridge.yang** are base model.

**ietf-interfaces@2014-05-08.yang** defines the **ietf-interfaces** model, and **ieee802-dot1q-bridge.yang** defines the **ieee802-dot1q-bridge** model.

**ieee802-dot1q-preemption.yang** and **ieee802-dot1q-sched.yang** are augment models of **ietf-interfaces@2014-05-08.yang**. **ieee802-dot1q-preemption.yang** adds qbu feature. **ieee802-dot1q-sched.yang** adds qbv feature.

**ieee802-dot1q-stream-filters-gates.yang** and **ieee802-dot1q-psfp.yang** are augment models of **ieee802-dot1q-bridge**. **ieee802-dot1q-stream-filters-gates.yang** adds stream-filters and stream-gates feature. **ieee802-dot1q-psfp.yang** adds qci-flow-meters feature and some supplements to stream-filters and stream-gate.

Especially, because there have no models about 802.1CB in [yang](https://github.com/YangModels/yang), we add **ieee802-dot1q-cb-stream-identification.yang** which based on *IEEE P802.1CB™/D2.8*. It will be replaced when [yang](https://github.com/YangModels/yang) adds related models.

Flowing picture shows relationship between these models:

![model ralationsheep](./images/model-relation.png)

Folowing files show detail model's nodes information:

- [ietf-interface-model-tree](./cfginterfaces/interfaces-tree.txt)
- [ieee802-dot1q-bridge](./cfgbridges/bridges-tree.txt)

## transAPI source files

It's structure is as below:
```
transAPI
│
│───cfgbridges			// Source files of transAPI cfgbridges
│   |   bridges.c
│   |   bridges.h
│   |   ieee802-dot1q-cb-stream-identification.yang
│   └─examples			// Instance examples
│       |   qci_instance.xml
│
│───cfgbridges-cb		// Source files of parsing cb configuration
│   |   parse_cb_node.h
│   |   parse_cb_node.c
│   └─examples			// Instance examples
│       |   stream_id_instance.xml
│
│───cfgbridges-qci		// Source files of parsing qci configuration
│   |   parse_qci_node.h
│   |   parse_qci_node.c
│   └─examples			// Instance examples
│       |   flow_meters_instance.xml
│       |   strean_filters_instance.xml
│       |   stream_gates_instance.xml
│
│───common			// Common APIs For all transAPIs running on the device
│   |  json_node_access.c	// APIs to access json node
│   |  json_node_access.h
│   |  xml_node_access.c	// APIs to access xml node
│   |  xml_node_access.h
│
│───platform			// Definitions and APIs dependent on specific platform
│   |  platform.c
│   |  platform.h
│
│───cfginterfaces		// Source files of transAPI cfginterfaces
│   |  interface.c
│   |  interface.h
│   └─examples			// Instance examples
│       |   qbv_qbu_instance.xml
│
│───cfginterfaces-qbv		// Source files of parsing qbv configuration
│   |  parse_qbv_node.c
│   |  parse_qbv_node.h
│   └─examples			// Instance examples
│       |   qbv_instance.xml
│
└───cfginterfaces-qbu		// Source files of parsing qbu configuration
    |  parse_qbu_node.c
    |  parse_qbu_node.h
    └─examples			// Instance examples
        |   qbu_instance.xml
```
Now, there have two transAPIs **cfgbridges** and **cfginterfaces**. TSN features like qbv, qbu and qci, are are part of these two transAPIs.
