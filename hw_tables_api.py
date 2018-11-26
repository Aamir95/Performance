#!/usr/bin/env python

#
# Copyright (c) 2018 Sarah Tollman
# All rights reserved.
#
# This software was developed by Stanford University and the University of Cambridge Computer Laboratory
# under National Science Foundation under Grant No. CNS-0855268,
# the University of Cambridge Computer Laboratory under EPSRC INTERNET Project EP/H040536/1 and
# by the University of Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"),
# as part of the DARPA MRC research programme.
#
# @NETFPGA_LICENSE_HEADER_START@
#
# Licensed to NetFPGA C.I.C. (NetFPGA) under one or more contributor
# license agreements.  See the NOTICE file distributed with this work for
# additional information regarding copyright ownership.  NetFPGA licenses this
# file to you under the NetFPGA Hardware-Software License, Version 1.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#   http://www.netfpga-cic.org
#
# Unless required by applicable law or agreed to in writing, Work distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations under the License.
#
# @NETFPGA_LICENSE_HEADER_END@
#

from collections import namedtuple

import sys, os
from addr_conversions import *
sys.path.append(os.path.expandvars('$P4_PROJECT_DIR/sw/CLI'))
import p4_tables_api

"""
In our solution, these dictionaries are keyed by the
table name and the value is a lambda function that converts
period delimited IP addresses and colon delimited MAC addresses
to integers before calling the p4_tables_api functions,
and convert the return values back from integers.

e.g.

KEYS_TO_NUMERIC = {
    'arp_cache_table':
        # arp_cache_table is keyed by an IP address
        lambda keys: [ip_to_int(keys[0])]
}

DATA_TO_NUMERIC = {
    'arp_cache_table':
        # arp_cache_table invokes an action which accepts as
        # input a MAC address
        lambda action_data: [mac_to_int(action_data[0])]
}

You do not have to do the conversion this way, but you will need
to update the api calls below otherwise.

"""

KEYS_TO_NUMERIC = {
    'mac_to_port':
        # mac_to_port is keyed by an mac address
        lambda keys: [mac_to_int(keys[0])],
}

DATA_TO_NUMERIC = {
    'mac_to_port':
        # mac_to_port invokes an action which accepts a port
        lambda action_data: action_data,
}

def table_cam_add_entry(table_name, keys, action_name, action_data):
    keys = KEYS_TO_NUMERIC[table_name](keys)
    action_data = DATA_TO_NUMERIC[table_name](action_data)
    p4_tables_api.table_cam_add_entry(table_name, keys, action_name, action_data)

def table_cam_delete_entry(table_name, keys):
    keys = KEYS_TO_NUMERIC[table_name](keys)
    p4_tables_api.table_cam_delete_entry(table_name, keys)

TCAM_entry = namedtuple('TCAM_entry', ['addr', 'key', 'mask', 'action_name', 'action_data'])

def lpm_to_tcam(lpm_dict):
    lpm_entries = lpm_dict.sorted_entries()
    tcam_entries = []

    addr = 0
    for e in lpm_entries:
        mask = 0
        for i in range(e.prefix_len):
            mask += 1 << (31 - i)
        try:
            # val should be (action_name, action_data)
            action_name, action_data = e.val
            tcam_entries.append(TCAM_entry(addr, e.key, mask, action_name, action_data))
            addr += 1
        except:
            pass

    return tcam_entries

def table_lpm_load_dataset(table_name, lpm_dict):
    p4_tables_api.table_tcam_clean(table_name)
    map(lambda e: p4_tables_api.table_tcam_write_entry(table_name, \
            e.addr, [e.key], [e.mask], e.action_name, \
            DATA_TO_NUMERIC[table_name](e.action_data)),
            lpm_to_tcam(lpm_dict))
