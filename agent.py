#!/usr/bin/env python

from headers import Control
from routing_consts import *
import ast
import socket
import sys
import os

BACKLOG = 128

class Agent(object):
    # TODO lots of error checking and sanitizing for style

    def __init__(self, thrift_port, port, verbose=False):
        self.thrift_port = thrift_port
        self.port = port
	self.verbose = verbose
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', port))
        self.sock.listen(BACKLOG)
        self.ack_pkt = Control(type=Control.types_reverse['ack'])
        self.tables_to_clear = []

    def listen_for_pkts(self):
        """
        Listens on a port for an incoming connection and parses messages
        as control packets. Sends back ACKs.
        """
	self.verbose_msg('waiting for connection')
	conn, addr = self.sock.accept()
	self.verbose_msg('connected to (%s, %s)' % addr)

        while True:
            try:
		self.verbose_msg('waiting for message')
                message = conn.recv(MAX_MSG_SIZE)
		if not message:
		    break
                pkt = Control(message)
                if pkt.type not in Control.types:
                    raise Exception('Unknown control message: %s' % message)

		self.verbose_msg('got control packet')
		if self.verbose:
		    pkt.show()
		    sys.stdout.flush()

                ctl_type = Control.types[pkt.type]
                if ctl_type == 'test':
                    commands = ast.literal_eval(str(pkt.payload))

                    self.clear_tables()
                    for cmd in commands:
                        self.execute_cmd(cmd)

                    self.send_ack(conn, pkt)

                elif ctl_type == 'ping':
		    self.verbose_msg('received ping')
                    self.send_ack(conn, pkt)

                elif ctl_type == 'end':
		    self.verbose_msg('received message to shut down')
                    self.send_ack(conn, pkt)
                    break

            except Exception as e:
	    	self.verbose_msg('received exception: %s' % e.message)
            except:
	    	self.verbose_msg('received some other exception')

	self.verbose_msg('shutting down')
	conn.close()

    def send_ack(self, conn, pkt):
        """ Sends an ACK control packet with the proper sequence #. """
	self.verbose_msg('sending ACK back')
        ack_copy = self.ack_pkt.copy()
        ack_copy.seqno = pkt.seqno
        conn.send(bytes(ack_copy))

    def verbose_msg(self, msg):
	if self.verbose:
	    print '[Agent] ', msg
	    sys.stdout.flush()

    def clear_tables(self):
        """ Should be called before calling handle_cmd on a new test.  """
        raise NotImplementedError("clear_tables should be implemented by a subclass.")

    def execute_cmd(self, cmd):
        raise NotImplementedError("handle_cmd should be implemented by a subclass.")


class BMV2Agent(Agent):

    def __init__(self, thrift_port, port, verbose=False):
        super(BMV2Agent, self).__init__(thrift_port, port, verbose)
        self.sw_cmd = 'simple_switch_CLI --pre SimplePreLAG --thrift-port %s' % self.thrift_port

    def clear_tables(self):
        for table in self.tables_to_clear:
            clear_cmd = "echo 'table_clear %s' | %s > /dev/null" % (table, self.sw_cmd)
            reset_cmd = "echo 'table_reset_default %s' | %s > /dev/null" % (table, self.sw_cmd)
	    self.verbose_msg('sesetting table %s' % table)
            subprocess.call(clear_cmd, shell=True)
            subprocess.call(reset_cmd, shell=True)

        self.tables_to_clear = []

    def execute_cmd(self, cmd):
        """ Executes a table command. """
	self.verbose_msg('executing command: %s' % cmd)
        sw_cmd = "echo '%s' | %s > /dev/null" % (cmd, self.sw_cmd)
        subprocess.call(sw_cmd, shell=True)
        # Save the table name in tables_to_clear to remove after testing.
        self.tables_to_clear.append(cmd.split(' ')[1])


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--thrift-port', required=True,
                        help='thrift port of switch', type=int)
    parser.add_argument('--port', required=True,
                        help='port agent listens on', type=int)
    parser.add_argument('--verbose', action='store_true',
                        help='verbose option') 
    args = parser.parse_args()

    agent = BMV2Agent(args.thrift_port, args.port, args.verbose)
    agent.listen_for_pkts()
