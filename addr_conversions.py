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

import re
import socket, struct
from ipaddress import IPv4Address

MAC_STR_REGEX = r'([\dA-Fa-f]{2}:){5}[\dA-Fa-f]{2}'

def ip_to_int(key):
    return int(IPv4Address(unicode(key)))

def int_to_ip(key):
    return str(IPv4Address(key))

def mac_to_int(key):
    if type(key) == unicode: key = str(key)
    if str != type(key) or 17 != len(key) or not re.match(MAC_STR_REGEX, key):
        raise ValueError

    return int(key.translate(None, ":.- "), 16)

def int_to_mac(key):
    if int != type(key):
        raise ValueError

    mac_hex = "{:012x}".format(key)
    mac_str = ":".join(mac_hex[i:i+2] for i in range(0, len(mac_hex), 2))

    return mac_str

def prefix_len_to_mask(prefix_len):
    if int != type(prefix_len):
        raise ValueError

    mask = 0
    for i in range(prefix_len):
        mask |= 1 << (31 - i)
    return int_to_ip(mask)

def mask_to_prefix_len(mask):
    mask = ip_to_int(mask)
    if 0 == mask: return 0

    num_zeros = 0
    while mask % 2 == 0:
        num_zeros += 1
        mask = mask >> 1
    prefix_len = 32 - num_zeros

    return prefix_len

# convert a long to an IP
def long2ip(l):
    packedIP = struct.pack("!L", l)
    return socket.inet_ntoa(packedIP)
