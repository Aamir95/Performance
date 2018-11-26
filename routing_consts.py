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

from scapy.all import *
from collections import namedtuple

DIG_LOCAL_IP = 1
NUM_CALIB_PKTS = 300
MAX_MSG_SIZE = 1024

PERF_ETHER_TYPE = 0x811
MIN_PACKET_LEN = 64
ETH_BROADCAST = 'ff:ff:ff:ff:ff:ff'
DEFAULT_MASK = '255.255.255.254'

nf_port_map = {'nf0': 0b00000001, 'nf1': 0b00000100, 'nf2': 0b00010000, \
    'nf3': 0b01000000, 'dma0': 0b00000010}

Iface = namedtuple('Iface', ['port', 'ip', 'mask', 'mac'])
