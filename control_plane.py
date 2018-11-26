#!/usr/bin/env python

from scapy.all import *
import numpy as np
import binascii
import ast
import yaml
import json
import subprocess
import sys
import time
import os
import tqdm
from threading import Thread, Semaphore
import report_generator

from headers import Digest_data, Perf, Control
import hw_tables_api
from routing_consts import *
from cp_config import HW_config, DMA_IFACE
from test import Test

FNULL = open(os.devnull, 'w')

class Control_plane(object):
    """
    The control plane sets up the system components, prepares tests cases,
    sends the data plane test packets, and aggregates statistics.
    """
    def __init__(self, config, params_dict, verbose=False):
        self.sendp = config.sendp
        self.ifaces = config.ifaces
        self.verbose = verbose
        self.p4prog = params_dict['p4prog']
	self.is_loopback = 'loopback-if' in params_dict
        self.calib_prog = None if self.is_loopback else params_dict['calib-prog']
        self.dut_mac = params_dict['dut-mac']
        self.dut_host = params_dict['dut-host']
        self.dut_workdir = params_dict['dut-workdir']
        self.agent_prog = params_dict['agent-prog']
        self.agent_port = params_dict['agent-port']
        self.dut_port = params_dict['dut-port']
        if self.dut_host.find('@') == -1:
	    self.dut_node = self.dut_host
	else:
	    self.dut_node = self.dut_host[self.dut_host.find('@')+1:]
	self.dut_node = socket.gethostbyname(self.dut_node)

	self.test_times = params_dict['test-times']
        self.tests = []
        self.agent = None
	self.agent_socket = None
        self.switch = None
        self.min_rtt = 0
        self.seqno = 0		# TODO seed this randomly?
	self.response = None
	self.listening_thread = Thread(target=self.run_hw)
	self.listening_thread.daemon = True
	self.listening_thread.start()
	self.sema = Semaphore(value=0)	# TODO better communication method that incorporates timeout

    def run_hw(self):
        sniff(iface=DMA_IFACE, prn=self.handle_packet, count=0)

    # a packet is valid if the digest code and ethertype are valid
    def pkt_valid(self, pkt):
	if pkt[Digest_data].digest_code != DIG_LOCAL_IP or Ether not in pkt:
	    return False
	ether_payload = pkt[Ether].payload
	perf = Perf(str(ether_payload))
        return Perf in perf and perf[Perf].seqno == self.seqno

    def handle_packet(self, pkt):
        pkt = Digest_data(str(pkt))
        if not self.pkt_valid(pkt):
	    return
	self.response = Perf(str(pkt[Ether].payload))
	self.sema.release()

    def calibrate_system(self):
        """ Determine RTT by running the calibration program on the DUT. """
	if self.calib_prog:
	    json_file = self.compile_prog(self.calib_prog)
	    remote_json_path = self.move_prog(json_file)
	    self.start_switch(remote_json_path)
	    time.sleep(3)        # This is a hack to wait for the switch

        # Now switch is running, send calibration packets to the dataplane
	if self.is_loopback:
            eth_src = self.ifaces['loopback'].mac
            eth_dst = eth_src
	else:
            eth_src = self.ifaces['to_dut'].mac
            eth_dst = self.dut_mac

        calib_pkt = Ether(src=eth_src, dst=eth_dst, type=PERF_ETHER_TYPE)/Perf()
	pbar = tqdm.tqdm(range(NUM_CALIB_PKTS))
        for i in pbar:
            calib_copy = calib_pkt.copy()
            calib_copy[Perf].seqno = self.seqno
            self.sendp(calib_copy)
	    self.sema.acquire() # wait for response
            rtt = self.response[Perf].tse - self.response[Perf].tss
            self.min_rtt = rtt if self.min_rtt == 0 else min(rtt, self.min_rtt)
            self.seqno += 1
	    if i % (NUM_CALIB_PKTS / 10) == 0:
		pbar.set_description('MinRTT: %d' % self.min_rtt)

    def start_system(self):
        """ Sets up the system components and participants.  """

        # Generates and store test cases by parsing the output of p4pktgen.
        json_file = self.compile_prog(self.p4prog)
	print 'Generating tests from %s' % json_file
	time.sleep(3)
        subprocess.call('p4pktgen %s > p4pktgen.log 2>&1' % json_file, shell=True)

        # Extract the test cases!
        tests_dict = json.load(open('test-cases.json', 'r'))
        for test in tests_dict:
	    test_obj = Test(test)
	    if test_obj.valid:
		self.tests.append(Test(test))
	print 'Found %d possible tests' % len(self.tests)

        remote_json_path = self.move_prog(json_file)
        self.start_switch(remote_json_path)
        time.sleep(3)        # This is a hack to wait for the switch

        # SSH into the DUT and start the agent listening on the agent port
        # and knows the DUT port.
        ssh_cmd = 'ssh %s' % self.dut_host
        agent_cmd = ' '.join((ssh_cmd,
                             '"%s --thrift-port %s',
			     '--verbose' if self.verbose else '',
                             '--port %s &"')) % (self.agent_prog, self.dut_port,
                                                 self.agent_port)
	print 'Spawning agent on port %s with thrift port %s' % (self.agent_port, self.dut_port)
        self.agent = subprocess.Popen(agent_cmd, shell=True)
        # TODO do handshake and bidirectional communication with the agent
        time.sleep(3)   # this is a HACK!
        self.agent_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.agent_socket.connect((self.dut_node, self.agent_port))
	print 'Spawned and connected to the agent'

    def start_tests(self):
        """
        For each test, sends the agent table commands, then sends/tracks
        packets to the performance data plane. Runs each test multiple times.
        """
        for i in range(len(self.tests)):
	    print 'Starting test %d/%d' % (i+1, len(self.tests))
	    test = self.tests[i]

            # Tell agent the table commands
            ctl = Control(seqno=self.seqno, type=Control.types_reverse['test'])
            cmd_pkt = ctl / Raw(load=str(test.table_cmds))
            response = self.send_agent_pkt(cmd_pkt)  # TODO sanitize packet
            self.seqno += 1

            total_time = 0
            port, pkt = test.packets[0].port, test.packets[0].pkt
            pkt[Ether].src = self.ifaces['to_dut'].mac
            pkt[Ether].dst = self.dut_mac

	    pbar = tqdm.tqdm(range(self.test_times))
            for i in pbar:
                pkt_copy = pkt.copy()
                pkt_copy[Perf].seqno = self.seqno
                self.sendp(pkt_copy)
		self.sema.acquire() # wait for response
                delay = self.response[Perf].tse - self.response[Perf].tss - self.min_rtt
                test.packets[0].times.append(delay)
                self.seqno += 1

    def print_test_results(self):
        """ Print stats from the list, self.tests. """
        report_generator.generate_report(self.tests, self.p4prog,
                                       self.is_loopback, self.calib_prog,
                                       self.dut_host)

    def clean_up(self):
        """ Tears down existing remote switch and agent. """
        if self.switch is not None:
            ssh_cmd = 'ssh %s' % self.dut_host
            switch_cmd = ' '.join((ssh_cmd, '"sudo pkill simple_switch"'))
            subprocess.call(switch_cmd, shell=True)
            self.switch.kill()
            self.switch = None

        if self.agent is not None:
            ctl_pkt = Control(seqno=self.seqno, type=Control.types_reverse['end'])
            response = self.send_agent_pkt(ctl_pkt)  # TODO sanitize packet
            self.seqno += 1
            self.agent.kill()
            self.agent = None
	    self.agent_socket.close()

    @staticmethod
    def compile_prog(prog):
        """ Compiles p4 program. """
        json_file = os.path.splitext(prog)[0] + '.json'
        compile_cmd = 'p4c-bm2-ss --p4v 16 -o %s %s' % (json_file, prog)
	print 'Compiling the P4 program: ' + compile_cmd
        subprocess.call(compile_cmd, shell=True, stdout=FNULL, stderr=FNULL)
        return json_file

    def move_prog(self, json_prog):
        """ Move a copy to the DUT. """
        remote_dir = '%s:%s' % (self.dut_host, self.dut_workdir)
        move_json_cmd = 'rsync -av %s %s:%s/' % (json_prog, self.dut_host, self.dut_workdir)
	print 'Moving program file: ' + move_json_cmd
        subprocess.call(move_json_cmd, shell=True, stdout=FNULL)
        remote_json_path = os.path.join(self.dut_workdir, json_prog)
        return remote_json_path

    def start_switch(self, remote_json_path):
        """ SSH into the DUT and start the switch listening on the DUT port. """
        ssh_cmd = 'ssh %s' % self.dut_host
        switch_cmd = ' '.join((ssh_cmd,
                              '"sudo simple_switch -i 0@eth1',
                              '--thrift-port %s %s &"')) % (self.dut_port,
                                                            remote_json_path)
	print 'Starting switch: ' + switch_cmd
        self.switch = subprocess.Popen(switch_cmd, shell=True, stdout=FNULL)

    def send_agent_pkt(self, pkt):
	if pkt[Control].type == Control.types_reverse['test']:
	    print 'Sending agent commands:'
	    cmds = ast.literal_eval(str(pkt.payload))
	    for cmd in cmds:
	        print '\t %s' % cmd
	    print ''
	if pkt[Control].type == Control.types_reverse['end']:
	    print 'Sending agent END signal'

        self.agent_socket.send(bytes(pkt))
        response = self.agent_socket.recv(MAX_MSG_SIZE)
        return response


def load_params(param_file):
    with open(param_file, 'r') as cfg:
        try:
            config_dict = (yaml.load(cfg))

	    assert 'calib' in config_dict
	    assert config_dict['calib'] in ['loopback', 'calib']
	    if config_dict['calib'] == 'loopback':
		assert 'loopback-if' in config_dict
	    else:
		assert 'calib-prog' in config_dict

            assert 'p4prog' in config_dict
            assert 'dut-mac' in config_dict
            assert 'dut-host' in config_dict
            assert 'dut-workdir' in config_dict
            assert 'dut-port' in config_dict

            assert 'agent-prog' in config_dict
            assert 'agent-port' in config_dict
            return config_dict

        except yaml.YAMLError as exc:
            print(exc)
            exit(1)

def load_required_ifaces(ifaces, tables_api):
    print 'Initializing table entries...'
    for name in ifaces:
	iface = ifaces[name]
	print 'Adding iface %s to mac_to_port: %s -> %s' % (name, iface.mac, iface.port)
        tables_api.table_cam_add_entry('mac_to_port', [iface.mac], 'set_dst_port', [iface.port])

# instantiate and run the control plane with runtime arguments
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--params-file', required=True,
                        help='configuration file', type=str)
    parser.add_argument('--verbose', action='store_true',
                        help='verbose mode')
    args = parser.parse_args()

    if args.verbose:
	FNULL = sys.stdout

    params_dict = load_params(args.params_file)

    config = HW_config
    if 'loopback-if' in params_dict:
	loopback_if = Iface(port=nf_port_map[params_dict['loopback-if']],
			    ip='10.0.0.2', mask=DEFAULT_MASK,
			    mac='08:11:11:11:11:12')
	ifaces = config.ifaces.copy()
	ifaces.update({'loopback': loopback_if})
	config = config._replace(ifaces=ifaces)

    load_required_ifaces(config.ifaces, config.tables_api)

    cp = Control_plane(config, params_dict, args.verbose)
    try:
        print('Calibrating system')
        cp.calibrate_system()
        print('Cleaning up calibration')
        cp.clean_up()
        print('Starting system')
        cp.start_system()
        print('Starting tests')
        cp.start_tests()
        print('Printing test results')
        cp.print_test_results()
        print('Cleaning up system')
    finally:
	cp.clean_up()
