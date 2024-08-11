# MIT License
# This file is part of Raw Ethernet Packet Generator
# See https://github.com/shikharbhargava/raw-packet-eth-win for more information
# Copyright (C) Shikhar Bhargava

"""
Raw Ethernet Packet Generator is a CLI packet generator tool for ethernet on Windows 10/11.
It allows you to create and send any possible packet or sequence of packets on the ethernet link.
It is very simple to use, powerful and supports many adjustments of parameters while sending.
"""

import os
import sys
import re
import time
#import json
import random
import textwrap

from argparse import ArgumentParser
from colorama import Fore, Style

from scapy.all import Raw, srp, sendp, send
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.sendrecv import _send
from scapy.arch.windows import get_windows_if_list

PROG_NAME = os.path.splitext(sys.argv[0])[0]
PROG_VERSION = '1.01'

IP_PROTO_ICMP = 1
IP_PROTO_UDP = 17
IP_PROTO_TCP = 6
GOOSE_ETH_TYPE = 0x88b8  # GOOSE
GOOSE_ETH_TYPE_HEX = hex(GOOSE_ETH_TYPE)
IPV4_ETH_TYPE = 0x0800
IPV4_ETH_TYPE_HEX = hex(IPV4_ETH_TYPE)

OPTIONS_REGEX = r'(((-){1,2}[a-z_]+)|((-){1,2}[A-Z]))([ \,\]])(([A-Z\-]+){0,1})'
ALL_OPTIONS_REGEX = r'(((-){1}[a-z_]+)|((-){1,2}[A-Z]))([ \,])(([A-Z\-]+){0,1}), ((-){2}[a-z_]+)([ \,])(([A-Z\-]+){0,1})'
TAB_CORRECTION_REGEX = r'(.+)([a-zA-Z])([\n]*   +)(.+)'
USEAGE_REGEX = r'(usage:.+)((\n)( +)(.+))+'

IP_REGEX = r'^(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$'
MAC_REGEX = r'^((([0-9A-Fa-f]{2}[:]){5})|(([0-9A-Fa-f]{2}[-]){5}))([0-9A-Fa-f]{2})$'
HEX_REGEX = r'^(0x){0,1}[0-9A-Fa-f]+$'
HEX_ETHER_TYPE_REGEX = r'^(0x){0,1}[0-9A-Fa-f]{1,4}$'
TIME_REGEX = r'^([0-9]+|[0-9]+\.[0-9]+|\.[0-9]+)(ms|s|m|h|d)$'

def find_max_line_length(paragraph):
    lines = paragraph.split('\n')
    max_length = max(len(line) for line in lines)
    return max_length

def split_string_with_textwrap(input_str, max_length):
    return textwrap.wrap(input_str, width=max_length)

class MyArgumentParser(ArgumentParser):
    def error(self, message):
        print_error(f'{message}')
        self.print_help()
        sys.exit(1)

    def _print_message(self, message, file=None):
        if message:
            if message.startswith('usage'):
                max_length = find_max_line_length(message)
                results = re.search(USEAGE_REGEX, message)
                usage_str = ''
                if results is not None:
                    usage_str = results.group()
                message = re.sub(r'\n    +', '       ', message)
                message = re.sub(r'(    +)(.+)([^ ])    +(.+)', r'\1\2\3\4', message)
                # Correcting usage line
                if results is not None:
                    message = re.sub(r'(usage:.+)', usage_str, message)
                message = re.sub(ALL_OPTIONS_REGEX, r'\1, \9 \7', message)
                results = re.findall(TAB_CORRECTION_REGEX, message)
                max_size = 0
                for r in results:
                    s = len(''.join(r[0:2]))
                    if s > max_size:
                        max_size = s
                colmn_size = (int(max_size/4) + 1) * 4
                for r in results:
                    first = ''.join(r[0:2])
                    replace_str = first + ' ' * (colmn_size - len(first)) + r[3]
                    replace_list = split_string_with_textwrap(replace_str, max_length)
                    replace_str = replace_list[0]
                    for i in range(1, len(replace_list)):
                        next_line = ' ' * colmn_size + replace_list[i]
                        new_replace_list = split_string_with_textwrap(next_line, max_length)
                        next_line = new_replace_list[0]
                        for j in range(1, len(new_replace_list)):
                            next_line = next_line + '\n' + ' ' * colmn_size + new_replace_list[j]
                        replace_str = replace_str + '\n' + next_line
                    message = message.replace(''.join(r[0:]), replace_str)
                message = re.sub(OPTIONS_REGEX, fr'{Fore.YELLOW}\1{Style.RESET_ALL}\6{Fore.GREEN}\7{Style.RESET_ALL}', message)
                message = (f'{Fore.YELLOW}program{Style.RESET_ALL}:'
                           f' {Fore.CYAN}{PROG_NAME} {Fore.YELLOW}version{Style.RESET_ALL}:'
                           f' {Fore.CYAN}{PROG_VERSION}{Style.RESET_ALL}\n\n{message}')
                message = message.replace('usage', f'{Fore.YELLOW}usage{Style.RESET_ALL}')
                message = message.replace('options', f'{Fore.YELLOW}options{Style.RESET_ALL}')
                message = message.replace(self.prog, f'{Fore.CYAN}{self.prog}{Style.RESET_ALL}')
            print(message)

def agruments():
    parser = MyArgumentParser(description='Sends raw packets on an interface.')
    parser.add_argument('-i', '--interface', metavar='INTERFACE-NAME', required=True, help='Output interface name')
    parser.add_argument('-s','--src_mac', metavar='SRC-MAC-ADDRESS', help='Source MAC Address. Optional,'
                                                                           ' if not provided then mac address of the itherface will be used')
    parser.add_argument('-d', '--dst_mac', metavar='DST-MAC-ADDRESS', help='Sestination mac address')
    parser.add_argument('-e', '--ether_type', metavar='ETHER-TYPE', help='Ethernet type in hex, required')
    parser.add_argument('-S', '--src_ip', metavar='SRC-IP-ADDRESS', help='Source ipv4 address, required if ethernet type is 0x0800 (ipv4)')
    parser.add_argument('-D', '--dst_ip', metavar='DST-IP-ADDRESS', help='Destination ipv4 address, required if ethernet type is 0x0800 (ipv4)')
    parser.add_argument('-P', '--ip_proto', type=int, metavar='IP-PROTO', help='IPv4 Protocol type, required if ethernet type is 0x0800 (ipv4)')
    parser.add_argument('-p', '--payload', metavar='PAYLOAD-HEX-STREAM', help='packet payload in hex stream')
    parser.add_argument('-f', '--payload_file', metavar='PAYLOAD-FILE', help='Packet payload file in hex stream')
    parser.add_argument('-c', '--packet_count', type=int, metavar='PACKET-COUNT', help='Number of packet to be sent [default=1]')
    parser.add_argument('-I', '--packet_interval', metavar='PACKET-INTERVAL', help='Time delay between 2 consecutive packets'
                                                                                   ' [default=1s, minimum=1ms, supported units={ms,s,m,h,d}]')
    parser.add_argument('-t', '--tcp_server', metavar='PORT', help='Creates a TCP server')
    parser.add_argument('-u', '--udp_server', metavar='PORT', help='Creates a UDP server')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show output log')
    parser.add_argument('-a', '--arp', action='store_true', help='Resolve mac address for an IPv4 address by sending ARP requests, use'
                                                                 ' -i option for selecting interface, -D option for destination address,'
                                                                 ' -c option for retry count and -I option for timeout time')

    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])
    return args, parser

def sleep(x):
    time.sleep(x)
def msleep(x):
    time.sleep(x/1000.0)
def usleep(x):
    time.sleep(x/1000000.0)

def print_error(*err : str, exit_prog=False):
    print(Fore.RED + 'ERROR: ' + ' '.join(err) + Style.RESET_ALL, file=sys.stderr)
    if exit_prog:
        sys.exit(1)

def print_warning(*err : str):
    print(Fore.YELLOW + 'WARNING: ' + ' '.join(err) + Style.RESET_ALL, file=sys.stderr)

class PacketGenerator:

    interface = ''
    src_mac = ''
    dst_mac = ''
    src_ip = ''
    dst_ip = ''
    eth_type = IPV4_ETH_TYPE
    ip_proto = 0
    count = 1
    interval = 1
    verbose=False
    arp = False
    tcp_server = False
    tcp_port = 0
    udp_server = False
    udp_port = 0
    payload = bytes()

    def __validate_ip(self, ip):
        if re.match(IP_REGEX, ip) is not None:
            return True, ip
        return False, ip

    def __validate_port(self, port_str):
        try:
            port = int(port_str)
            if 0 < port <= 0xFFFF:
                return True, port
            return False, 0
        except ValueError:
            return False, 0

    def __validate_mac(self, mac):
        if re.match(MAC_REGEX, mac) is not None:
            mac = mac.replace('-', ':')
            return True, mac
        return False, mac

    def __validate_ether_type(self, ether_type):
        if re.match(HEX_ETHER_TYPE_REGEX, ether_type) is not None:
            eth_type = int(ether_type, 16)
            return True, eth_type
        return False, 0

    def __validate_payload(self, payload):
        if re.match(HEX_REGEX, payload) is not None:
            payload = payload.removeprefix('0x')
            return True, payload
        return False, payload

    def __validate_payload_paload_file(self, payload_file):
        pay_str = ''
        pay_valid = False
        valid = False
        try:
            with open(payload_file, 'r', encoding='UTF-8') as file:
                data = file.read().replace('\n', '')
                pay_valid, pay_str = self.__validate_payload(data)
                valid = True
        except FileNotFoundError:
            valid = False
        return valid, pay_valid, pay_str

    def __convert_time_string_to_milliseconds(self, time_str, unit):
        value = 0.0
        value = float(time_str)
        if unit == 'ms':
            return value
        if unit == 's':
            value *= 1000
            return value
        if unit == 'm':
            value *= 1000 * 60
            return value
        if unit == 'h':
            value *= 1000 * 60 * 60
            return value
        if unit == 'd':
            value *= 1000 * 60 * 60 * 24
        return value

    def __validate_time(self, timestr):
        time_value = 0.0
        result = re.match(TIME_REGEX, timestr)
        if result is not None:
            time_value = self.__convert_time_string_to_milliseconds(result.group(1), result.group(2))
            return True, time_value
        return False, time_value

    def __send_ethernet_packet(self, src, dst, eth_type, payload, interface, count=1, interval=1, verbose=False):
        ether_frame = Ether(src=src, dst=dst, type=eth_type) / Raw(load=payload)
        #sendp(ether_frame, iface=interface)
        _send(ether_frame, lambda iface: iface.l2socket(), iface=interface, inter=interval/1000, count=count, verbose=verbose)

    def __icmp_checksum(self, icmp_packet : ICMP):
        del icmp_packet.chksum
        icmp_packet = ICMP(bytes(icmp_packet))
        return bytes(icmp_packet)

    def __udp_checksum(self, udp_packet : UDP):
        del udp_packet.chksum
        udp_packet = UDP(bytes(udp_packet))
        return bytes(udp_packet)

    def __tcp_checksum(self, tcp_packet : TCP):
        del tcp_packet.chksum
        tcp_packet = TCP(bytes(tcp_packet))
        return bytes(tcp_packet)

    def __regenerate_icmp_seq(self, payload : bytes):
        icmp_packet = ICMP(payload)
        icmp_packet.seq = random.randint(1, 0x00fe)
        return self.__icmp_checksum(icmp_packet)

    def __send_ethernet_packet_ip(self, src, dst, src_ip, dst_ip, ip_proto, payload, interface, count=1, interval=1, verbose=False):
        ip_packet_id = random.randint(1, 0x00fe)
        if ip_proto == IP_PROTO_ICMP:
            payload = self.__regenerate_icmp_seq(payload)
        elif ip_proto == IP_PROTO_UDP:
            payload = self.__udp_checksum(UDP(payload))
        ether_frame = Ether(src=src, dst=dst, type=IPV4_ETH_TYPE) / IP(src=src_ip, dst=dst_ip, proto=ip_proto, id=ip_packet_id) / Raw(load=payload)
        _send(ether_frame, lambda iface: iface.l2socket(), iface=interface, inter=interval/1000, count=count, verbose=verbose)
        ip_packet_id += 1

    def __send_ip_packet(self, src_ip, dst_ip, ip_proto, payload, count=1, interval=1, verbose=False):
        ip_packet_id = random.randint(1, 0x00fe)
        if ip_proto == IP_PROTO_ICMP:
            payload = self.__regenerate_icmp_seq(payload)
        elif ip_proto == IP_PROTO_UDP:
            payload = self.__udp_checksum(UDP(payload))
        packet = IP(src=src_ip, dst=dst_ip, proto=ip_proto, id=ip_packet_id) / Raw(load=payload)
        send(packet, inter=interval/1000, count=count, verbose=verbose)
        ip_packet_id += 1

    def __get_mac_address(self, interface_name):
        interfaces = get_windows_if_list()
        for iface in interfaces:
            if any(iface[x] == interface_name for x in ['name', 'guid', 'description', 'index']):
                return iface['mac'], iface['ips']
        return None, None

    def __arp_scan(self, iface, ip, interval, count):
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
        result, _ = srp(broadcast / arp_request, iface=iface, timeout=int(interval), retry=count, verbose=False)

        for _, received in result:
            return True, str(received.hwsrc)
        return False, ''

    def __init__(self):
        args, parser = agruments()

        src_mac_valid = False
        dst_mac_valid = False
        src_ip_valid = False
        dst_ip_valid = False
        eth_str = ''
        eth_type_valid = False
        payload_str = ''
        payload_valid = False
        payload_file = ''
        payload_file_valid = False
        interval_str = ''
        interval_valid = True
        tcp_port_str = ''
        tcp_port_valid = False
        udp_port_str = ''
        udp_port_valid = False

        for opt, arg in vars(args).items():
            if opt == 'arp' and arg is not None:
                self.arp = arg
            if opt == 'tcp_server' and arg is not None:
                tcp_port_str = arg
                self.tcp_server = True
                tcp_port_valid, self.tcp_port = self.__validate_port(arg)
            if opt == 'udp_server' and arg is not None:
                udp_port_str = arg
                self.udp_server = True
                udp_port_valid, self.udp_port = self.__validate_port(arg)
            if opt == 'interface' and arg is not None:
                self.interface = arg
            if opt == 'src_mac' and arg is not None:
                src_mac_valid, self.src_mac = self.__validate_mac(arg)
            if opt == 'dst_mac' and arg is not None:
                dst_mac_valid, self.dst_mac = self.__validate_mac(arg)
            if opt == 'ether_type' and arg is not None:
                eth_str = arg
                eth_type_valid, self.eth_type = self.__validate_ether_type(arg)
            if opt == 'src_ip' and arg is not None:
                src_ip_valid, self.src_ip = self.__validate_ip(arg)
            if opt == 'dst_ip' and arg is not None:
                dst_ip_valid, self.dst_ip = self.__validate_ip(arg)
            if opt == 'ip_proto' and arg is not None:
                self.ip_proto = arg
            if opt == 'payload' and arg is not None:
                payload_valid, payload_str = self.__validate_payload(arg)
            if opt == 'payload_file' and arg is not None:
                payload_file = arg
                payload_file_valid, payload_valid, payload_str = self.__validate_payload_paload_file(payload_file)
            if opt == 'packet_count' and arg is not None:
                self.count = arg
            if opt == 'packet_interval' and arg is not None:
                interval_str = arg
                interval_valid , self.interval = self.__validate_time(arg)
            if opt == 'verbose' and arg is not None:
                self.verbose=arg

        ips = None
        if self.src_mac == '':
            self.src_mac, ips = self.__get_mac_address(self.interface)
            if self.src_mac is None:
                print_error(f'Invalid interface: {self.interface}', exit_prog=True)
            src_mac_valid = True

        if not src_mac_valid:
            print_error(f'Invalid Source MAC address: {self.src_mac}', exit_prog=True)

        if interval_str != '' and not interval_valid:
            print_error(f'Invalid packet interval: {interval_str}', exit_prog=True)

        if not self.arp:
            if self.dst_mac == '' and self.dst_ip == '':
                parser.error('At-least one of the destination MAC or IPv4 address is required.')
            if self.dst_mac == '' and dst_ip_valid:
                if self.dst_ip == self.src_ip:
                    self.dst_mac = self.src_mac
                    dst_mac_valid = True
                else:
                    if self.verbose:
                        print(f'Sending Arp to {self.dst_ip} using interface {self.interface}, timeout time=1s, retry count={self.count}')
                    dst_mac_valid, self.dst_mac = self.__arp_scan(self.interface, self.dst_ip, 1, self.count)
                if dst_mac_valid and self.verbose:
                    print(f'Found mac address {self.dst_mac} for ip address {self.dst_ip}')
                if not dst_mac_valid:
                    print_error(f'Could not find MAC address for {self.dst_ip}', exit_prog=True)
            if self.dst_mac == '':
                print_error(f'Could not resolve MAC address for {self.dst_ip}', exit_prog=True)
            if not dst_mac_valid:
                print_error(f'Invalid Destination MAC address: {self.dst_mac}', exit_prog=True)

            if not eth_type_valid:
                print_error(f'Invalid ether type: {eth_str}', exit_prog=True)

            if self.eth_type == IPV4_ETH_TYPE:
                if self.src_ip == '':
                    parser.error(f'Source IPv4 address is required for ether type {IPV4_ETH_TYPE_HEX}')
                elif not src_ip_valid:
                    print_error(f'Invalid source address {self.src_ip}')
                elif self.src_mac == '' and ips is not None and self.src_ip not in ips:
                    print_warning(f'Source Address {self.src_ip} is not confgured on interface {self.interface}')
                if self.ip_proto == 0:
                    parser.error(f'IPv4 protocol type is required for ether type {IPV4_ETH_TYPE_HEX}')

            if payload_file != '' and not payload_file_valid:
                print_error(f'Invalid payload file  : {payload_file}', exit_prog=True)

            if not payload_valid:
                print_error(f'Invalid payload hex stream: {payload_str}', exit_prog=True)
        else:
            if self.dst_ip == '':
                parser.error('For ARP request destination IP address is required.')

        self.payload = bytes.fromhex(payload_str)

    def send_arp(self):
        if self.arp:
            print(f'Sending Arp to {self.dst_ip} using interface {self.interface}, timeout time={self.interval/1000}s, retry count={self.count}')
            found, mac = self.__arp_scan(self.interface, self.dst_ip, self.interval/1000, self.count)
            if found:
                print(f'Found mac address {mac} for ip address {self.dst_ip}')
            else:
                print(f'Could not find mac address for ip address {self.dst_ip}')

    def send(self):
        if self.arp:
            self.send_arp()
            return

        if self.eth_type == IPV4_ETH_TYPE:
            if self.ip_proto == IP_PROTO_TCP:
                print_error('TCP packet not yet supported.')
                return
            if self.src_ip == self.dst_ip:
                self.__send_ip_packet(self.src_ip,
                                    self.dst_ip,
                                    self.ip_proto,
                                    self.payload,
                                    self.count,
                                    self.interval,
                                    self.verbose)
            else:
                self.__send_ethernet_packet_ip(self.src_mac,
                                             self.dst_mac,
                                             self.src_ip,
                                             self.dst_ip,
                                             self.ip_proto,
                                             self.payload,
                                             self.interface,
                                             self.count,
                                             self.interval,
                                             self.verbose)
        else:
            self.__send_ethernet_packet(self.src_mac,
                                      self.dst_mac,
                                      self.eth_type,
                                      self.payload,
                                      self.interface,
                                      self.count,
                                      self.interval,
                                      self.verbose)


def main():
    gen = PacketGenerator()
    gen.send()

if __name__=="__main__":
    main()
