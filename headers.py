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
# Jestin Ma - added more headers
#

from scapy.all import *
from routing_consts import PERF_ETHER_TYPE

class Digest_data(Packet):
    name = 'Digest_data'
    fields_desc = [
        ByteField('src_port', 0),
        ByteField('digest_code', 0),
        LELongField('unused1', 0),
        LELongField('unused2', 0),
        LELongField('unused3', 0),
        LEIntField('unused4', 0),
        LEShortField('unused5', 0)
    ]
    def mysummary(self):
        return self.sprintf('src_port=%src_port% digest_code=%digest_code%')

class Perf(Packet):
    """
    The Perf layer is layered between Ethernet and IP/ARP to track time.
    """
    name = "Perf"
    fields_desc = [
        ShortField('seqno', 0),
        BitField('tss', 0x0, 32),
        BitField('tse', 0x0, 32)
    ]

class Control(Packet):
    """
    Control packets are sent between the performance control plane and agent
    plane to communicate table entries and ACKs.

    The payload for test packets will be a list of commands as strings.
    """
    name = "Control"
    types = { 1: 'test', 2: 'ping', 3: 'ack', 4: 'end' }
    types_reverse = { 'test': 1, 'ping': 2, 'ack': 3, 'end': 4}
    fields_desc = [
        ShortField('seqno', 0),
        ShortEnumField('type', 1, types)
    ]

bind_layers(Digest_data, Ether)
bind_layers(Ether, Perf, type=PERF_ETHER_TYPE)
