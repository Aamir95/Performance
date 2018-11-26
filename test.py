#!/usr/bin/env python

import binascii
from collections import namedtuple
from scapy.all import *
from headers import Perf

class TestPacket(object):
    def __init__(self, port, pkt):
        self.port = port
        self.pkt = pkt
        self.times = []

class Test(object):
    def __init__(self, test_dict):
        self.result = test_dict['result']
        self.expected_path = test_dict['expected_path']
        self.table_cmds = test_dict['ss_cli_setup_cmds']
        self.packets = []
        self.valid = False
        for pkt_info in test_dict['input_packets']:
            pkt_str = binascii.unhexlify(pkt_info['packet_hexstr'])
            pkt = Ether(pkt_str)
	    if Ether not in pkt:
                continue
            # Insert the Perf header that will be used.
            payload = pkt.getlayer(0).payload
            pkt.getlayer(0).remove_payload()
            pkt = pkt / Perf() / payload
            self.packets.append(TestPacket(port=pkt_info['port'], pkt=pkt))

	if len(self.packets) > 0:
	    self.valid = True
