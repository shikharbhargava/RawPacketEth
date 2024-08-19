# MIT License
# This file is part of Raw Ethernet Packet Generator
# See https://github.com/shikharbhargava/raw-packet-eth-win for more information
# Copyright (C) Shikhar Bhargava

"""
Raw Ethernet Packet Generator is a CLI packet generator tool for ethernet on Windows 10/11.
It allows you to create and send any possible packet or sequence of packets on the ethernet link.
It is very simple to use, powerful and supports many adjustments of parameters while sending.
"""

import sys
import os
import re
#import json
import random

from scapy.all import Raw, srp, send
#from scapy.all import sendp
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.sendrecv import _send
from scapy.arch.windows import get_windows_if_list

from utility.argparser import parse_arguments
from utility.printfunc import print_error, print_warning

VERSION = "1.0"

# Known IP Protocols
IP_PROTO_ICMP   = 0x01
IP_PROTO_UDP    = 0x11
IP_PROTO_TCP    = 0x06

# Known EtherType
IPV4_ETH_TYPE   = 0x0800
GOOSE_ETH_TYPE  = 0x88b8
# Known EtherType Hex String
IPV4_ETH_TYPE_HEX_STR   = hex(IPV4_ETH_TYPE)
GOOSE_ETH_TYPE_HEX_STR  = hex(GOOSE_ETH_TYPE)

class PacketGenerator:
    """
    PacketGenerator class parse and validates the parameters, also generates ethernet packets.
    """

    _IP_REGEX = r'^(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$'
    _MAC_REGEX = r'^((([0-9A-Fa-f]{2}[:]){5})|(([0-9A-Fa-f]{2}[-]){5}))([0-9A-Fa-f]{2})$'
    _HEX_REGEX = r'^(0x){0,1}[0-9A-Fa-f]+$'
    _HEX_ETHER_TYPE_REGEX = r'^(0x){0,1}[0-9A-Fa-f]{1,4}$'
    _TIME_REGEX = r'^([0-9]+|[0-9]+\.[0-9]+|\.[0-9]+)(ms|s|m|h|d)$'

    _interface = ''
    _src_mac = ''
    _dst_mac = ''
    _src_ip = ''
    _dst_ip = ''
    _eth_type = IPV4_ETH_TYPE
    _ip_proto = 0
    _count = 1
    _interval = 1
    _verbose=False
    _arp = False
    _tcp_server = False
    _tcp_port = 0
    _udp_server = False
    _udp_port = 0
    _payload = bytes()

    _src_mac_valid = False
    _dst_mac_valid = False
    _src_ip_valid = False
    _dst_ip_valid = False
    _eth_type_str = ''
    _eth_type_valid = False
    _payload_str = ''
    _payload_valid = False
    _payload_file = ''
    _payload_file_valid = False
    _interval_str = ''
    _interval_valid = True
    _tcp_port_str = ''
    _tcp_port_valid = False
    _udp_port_str = ''
    _udp_port_valid = False
    _ips = []

    def __validate_ip(self, ip):
        if re.match(self._IP_REGEX, ip) is not None:
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
        if re.match(self._MAC_REGEX, mac) is not None:
            mac = mac.replace('-', ':')
            return True, mac
        return False, mac

    def __validate_ether_type(self, ether_type):
        if re.match(self._HEX_ETHER_TYPE_REGEX, ether_type) is not None:
            eth_type = int(ether_type, 16)
            return True, eth_type
        return False, 0

    def __validate_payload(self, payload):
        if re.match(self._HEX_REGEX, payload) is not None:
            payload = payload.removeprefix('0x')
            return True, payload
        return False, payload

    def __validate_payload_paload_file(self):
        pay_str = ''
        pay_valid = False
        valid = False
        try:
            with open(self._payload_file, 'r', encoding='UTF-8') as file:
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
        result = re.match(self._TIME_REGEX, timestr)
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
        ether_frame = Ether(src=src, dst=dst, type=IPV4_ETH_TYPE) \
                        / IP(src=src_ip, dst=dst_ip, proto=ip_proto, id=ip_packet_id) \
                        / Raw(load=payload)
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

    def __extract_dst_mac_from_dst_ip(self):
        if self._dst_mac == '' and self._dst_ip_valid:
            if self._dst_ip == self._src_ip:
                self._dst_mac = self._src_mac
                self._dst_mac_valid = True
            else:
                if self._verbose:
                    print(f'Sending Arp to {self._dst_ip} using interface {self._interface}, timeout time=1s, retry count={1}')
                self._dst_mac_valid, self._dst_mac = self.__arp_scan(self._interface, self._dst_ip, 1, 1)
            if self._dst_mac_valid and self._verbose:
                print(f'Found mac address {self._dst_mac} for ip address {self._dst_ip}')
            if not self._dst_mac_valid:
                print_error(f'Could not find MAC address for {self._dst_ip}', exit_prog=True)

    def __validate_arp_arguments(self, parser):
        if self._dst_ip == '':
            parser.error('For ARP request destination IP address is required.')

    def __validate_non_arp_arguments(self,
                                     parser):

        if self._dst_mac == '' and self._dst_ip == '':
            parser.error('At-least one of the destination MAC or IPv4 address is required.')

        self.__extract_dst_mac_from_dst_ip()

        if self._dst_mac == '':
            print_error(f'Could not resolve MAC address for {self._dst_ip}', exit_prog=True)
        if not self._dst_mac_valid:
            print_error(f'Invalid Destination MAC address: {self._dst_mac}', exit_prog=True)

        if not self._eth_type_valid:
            print_error(f'Invalid ether type: {self._eth_type_str}', exit_prog=True)

        if self._eth_type == IPV4_ETH_TYPE:
            if self._src_ip == '':
                parser.error(f'Source IPv4 address is required for ether type {IPV4_ETH_TYPE_HEX_STR}')
            elif not self._src_ip_valid:
                print_error(f'Invalid source address {self._src_ip}')
            elif self._src_mac == '' and self._ips is not None and self._src_ip not in self._ips:
                print_warning(f'Source Address {self._src_ip} is not confgured on interface {self._interface}')
            if self._ip_proto == 0:
                parser.error(f'IPv4 protocol type is required for ether type {IPV4_ETH_TYPE_HEX_STR}')

        if self._payload_file != '' and not self._payload_file_valid:
            print_error(f'Invalid payload file  : {self._payload_file}', exit_prog=True)

        if not self._payload_valid:
            print_error(f'Invalid payload hex stream: {self._payload_str}', exit_prog=True)

    def __extract_validate_arguments(self, args, parser):

        for opt, arg in vars(args).items():
            if opt == 'arp' and arg is not None:
                self._arp = arg
            if opt == 'tcp_server' and arg is not None:
                self._tcp_port_str = arg
                self._tcp_server = True
                self._tcp_port_valid, self._tcp_port = self.__validate_port(arg)
            if opt == 'udp_server' and arg is not None:
                self._udp_port_str = arg
                self._udp_server = True
                self._udp_port_valid, self._udp_port = self.__validate_port(arg)
            if opt == 'interface' and arg is not None:
                self._interface = arg
            if opt == 'src_mac' and arg is not None:
                self._src_mac_valid, self._src_mac = self.__validate_mac(arg)
            if opt == 'dst_mac' and arg is not None:
                self._dst_mac_valid, self._dst_mac = self.__validate_mac(arg)
            if opt == 'ether_type' and arg is not None:
                self._eth_type_str = arg
                self._eth_type_valid, self._eth_type = self.__validate_ether_type(arg)
            if opt == 'src_ip' and arg is not None:
                self._src_ip_valid, self._src_ip = self.__validate_ip(arg)
            if opt == 'dst_ip' and arg is not None:
                self._dst_ip_valid, self._dst_ip = self.__validate_ip(arg)
            if opt == 'ip_proto' and arg is not None:
                self._ip_proto = arg
            if opt == 'payload' and arg is not None:
                self._payload_valid, self._payload_str = self.__validate_payload(arg)
            if opt == 'payload_file' and arg is not None:
                self._payload_file = arg
                self._payload_file_valid, self._payload_valid, self._payload_str = self.__validate_payload_paload_file()
            if opt == 'packet_count' and arg is not None:
                self._count = arg
            if opt == 'packet_interval' and arg is not None:
                self._interval_str = arg
                self._interval_valid , self._interval = self.__validate_time(arg)
            if opt == 'verbose' and arg is not None:
                self._verbose=arg

        if self._src_mac == '':
            self._src_mac, self._ips = self.__get_mac_address(self._interface)
            if self._src_mac is None:
                print_error(f'Invalid interface: {self._interface}', exit_prog=True)
            self._src_mac_valid = True

        if not self._src_mac_valid:
            print_error(f'Invalid Source MAC address: {self._src_mac}', exit_prog=True)

        if self._interval_str != '' and not self._interval_valid:
            print_error(f'Invalid packet interval: {self._interval_str}', exit_prog=True)

        if not self._arp:
            self.__validate_non_arp_arguments(parser)

            self._payload = bytes.fromhex(self._payload_str)
        else:
            self.__validate_arp_arguments(parser)

    def __init__(self, arguments:list):
        args, parser = parse_arguments(arguments, os.path.splitext(sys.argv[0])[0], VERSION)
        self.__extract_validate_arguments(args, parser)

    def send_arp(self):
        """
        sends preconfigures arp packet
        """
        if self._arp:
            print(f'Sending Arp to {self._dst_ip} using interface {self._interface},'
                  f' timeout time={self._interval/1000}s,'
                  f' retry count={self._count}')
            found, mac = self.__arp_scan(self._interface, self._dst_ip, self._interval/1000, self._count)
            if found:
                print(f'Found mac address {mac} for ip address {self._dst_ip}')
            else:
                print(f'Could not find mac address for ip address {self._dst_ip}')

    def send_packet(self):
        """
        sends preconfigures ethernet packets (also send ARP packet if it is configured)
        """
        if self._arp:
            self.send_arp()
            return

        if self._eth_type == IPV4_ETH_TYPE:
            if self._ip_proto == IP_PROTO_TCP:
                print_error('TCP packet not yet supported.')
                return
            if self._src_ip == self._dst_ip:
                self.__send_ip_packet(self._src_ip,
                                    self._dst_ip,
                                    self._ip_proto,
                                    self._payload,
                                    self._count,
                                    self._interval,
                                    self._verbose)
            else:
                self.__send_ethernet_packet_ip(self._src_mac,
                                             self._dst_mac,
                                             self._src_ip,
                                             self._dst_ip,
                                             self._ip_proto,
                                             self._payload,
                                             self._interface,
                                             self._count,
                                             self._interval,
                                             self._verbose)
        else:
            self.__send_ethernet_packet(self._src_mac,
                                      self._dst_mac,
                                      self._eth_type,
                                      self._payload,
                                      self._interface,
                                      self._count,
                                      self._interval,
                                      self._verbose)
