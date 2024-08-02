from scapy.all import Ether, Raw, IP, ARP, ICMP, TCP, UDP, srp, sendp, send
from scapy.sendrecv import _send
from scapy.utils import checksum
from scapy.arch.windows import get_windows_if_list
from colorama import Fore, Style
import sys
#import getopt
from argparse import ArgumentParser
import re
import time
import json
import random
import textwrap

prog_name = 'raw-packet-eth'
prog_version = '1.01'

options_regex = r'(((-){1,2}[a-z_]+)|((-){1,2}[A-Z]))([ \,\]])(([A-Z\-]+){0,1})'
all_options_regex = r'(((-){1}[a-z_]+)|((-){1,2}[A-Z]))([ \,])(([A-Z\-]+){0,1}), ((-){2}[a-z_]+)([ \,])(([A-Z\-]+){0,1})'
tab_correction_regex = r'(.+)([a-zA-Z])([\n]*   +)(.+)'
useage_regex = r'(usage:.+)((\n)( +)(.+))+'

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
        exit(1)
    def _print_message(self, message, file=None):
        if message:
            if message.startswith('usage'):
                maxLength = find_max_line_length(message)
                results = re.search(useage_regex, message)
                usage_str = ''
                if results is not None:
                    usage_str = results.group()
                message = re.sub(r'\n    +', '       ', message)
                message = re.sub(r'(    +)(.+)([^ ])    +(.+)', r'\1\2\3\4', message)
                # Correcting usage line
                if results is not None:
                    message = re.sub(r'(usage:.+)', usage_str, message)
                message = re.sub(all_options_regex, r'\1, \9 \7', message)
                results = re.findall(tab_correction_regex, message)
                max = 0
                for r in results:
                    j = ''.join(r[0:2])
                    s = len(j)
                    if s > max:
                        max = s
                tabs = int(max/4) + 1
                colmn_size = tabs * 4
                for r in results:
                    j = ''.join(r[0:2])
                    s = len(j)
                    space_count = colmn_size - s
                    spaces = ' ' * space_count
                    search = ''.join(r[0:])
                    replace_str = j + spaces + r[3]
                    replace_list = split_string_with_textwrap(replace_str, maxLength)
                    replace_str = replace_list[0]
                    for i in range(1, len(replace_list)):
                        replace_str = replace_str + '\n' + ' ' * colmn_size + replace_list[i]
                    message = message.replace(search, replace_str)
                message = re.sub(options_regex, r'{}\1{}\6{}\7{}'.format(Fore.YELLOW, Style.RESET_ALL, Fore.GREEN   , Style.RESET_ALL), message)
                message = f'{Fore.YELLOW}program{Style.RESET_ALL}: {Fore.CYAN}{prog_name} {Fore.YELLOW}version{Style.RESET_ALL}: {Fore.CYAN}{prog_version}{Style.RESET_ALL}\n\n{message}'
                message = message.replace('usage', f'{Fore.YELLOW}usage{Style.RESET_ALL}')
                message = message.replace('options', f'{Fore.YELLOW}options{Style.RESET_ALL}')
                message = message.replace(self.prog, f'{Fore.CYAN}{self.prog}{Style.RESET_ALL}')
            #message = f'[{col_base}]{message.strip()}[/{col_base}]'
            print(message)

def agruments():
    parser = MyArgumentParser(description='Sends raw packets on an interface.')
    parser.add_argument('-i', '--interface', metavar='INTERFACE-NAME', required=True, help='Output interface name')
    parser.add_argument('-s','--src_mac', metavar='SRC-MAC', help='Source MAC Address. Optional, if not provided then mac address of the itherface will be used')
    parser.add_argument('-d', '--dst_mac', metavar='DST-MAC', help='Sestination mac address')
    parser.add_argument('-e', '--ether_type', metavar='ETHER-TYPE', help='Ethernet type in hex, required')
    parser.add_argument('-S', '--src_ip', metavar='SRC-IP', help='Source ipv4 address, required if ethernet type is 0x0800 (ipv4)')
    parser.add_argument('-D', '--dst_ip', metavar='DST-IP', help='Destination ipv4 address, required if ethernet type is 0x0800 (ipv4)')
    parser.add_argument('-P', '--ip_proto', type=int, metavar='IP-PROTO', help='IPv4 Protocol type, required if ethernet type is 0x0800 (ipv4)')
    parser.add_argument('-p', '--payload', metavar='PAYLOAD-HEX-STREAM', help='{acket payload in hex stream')
    parser.add_argument('-f', '--payload_file', metavar='PAYLOAD-FILE', help='Packet payload file in hex stream')
    parser.add_argument('-c', '--packet_count', type=int, metavar='PACKET-COUNT', help='Number of packet to be sent [default=1]')
    parser.add_argument('-I', '--packet_interval', metavar='PACKET-INTERVAL', help='Time delay between 2 consecutive packets [default=1s, minimum=1ms, supported units={ms,s,m,h,d}]')
    parser.add_argument('-t', '--tcp_server', metavar='PORT', help='Creates a TCP server')
    parser.add_argument('-u', '--udp_server', metavar='PORT', help='Creates a UDP server')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show output log')
    parser.add_argument('-a', '--arp', action='store_true', help='Resolve mac address for an IPv4 address by sending ARP requests, use'
                                                                ' -i option for selecting interface, -D option for destination address,'
                                                                ' -c option for retry count and -I option for timeout time')

    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])
    return args, parser

sleep = lambda x: time.sleep(x)
msleep = lambda x: time.sleep(x/1000.0)
usleep = lambda x: time.sleep(x/1000000.0)

ip_regex = r'^(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$'
mac_regex = r'^((([0-9A-Fa-f]{2}[:]){5})|(([0-9A-Fa-f]{2}[-]){5}))([0-9A-Fa-f]{2})$'
hex_regex = r'^(0x){0,1}[0-9A-Fa-f]+$'
hex_ether_type_regex = r'^(0x){0,1}[0-9A-Fa-f]{1,4}$'
time_regex = r'^([0-9]+|[0-9]+\.[0-9]+|\.[0-9]+)(ms|s|m|h|d)$'

def validate_ip(ip):
    if re.match(ip_regex, ip) is not None:
        return True, ip
    return False, ip

def validate_port(port_str):
    try:
        port = int(port_str)
        if port > 0 and port <= 0xFFFF:
            return True, port
        else:
            return False, 0
    except ValueError:
        return False, 0

def validate_mac(mac):
    if re.match(mac_regex, mac) is not None:
        mac = arg.replace('-', ':')
        return True, mac
    return False, mac

def validate_ether_type(ether_type):
    if re.match(hex_ether_type_regex, ether_type) is not None:
        eth_type = int(arg, 16)
        return True, eth_type
    return False, 0

def validate_payload(payload):
    if re.match(hex_regex, payload) is not None:
        payload = payload.removeprefix('0x')
        return True, payload
    return False, payload

def validate_payload_paload_file(payload_file):
    str = ''
    pay_valid = False
    valid = False
    try:
        with open(payload_file, 'r') as file:
            data = file.read().replace('\n', '')
            pay_valid, str = validate_payload(data)
            valid = True
    except FileNotFoundError as e:
        valid = False
    return valid, pay_valid, str

def convert_time_string_to_milliseconds(time_str, unit):
    value = 0.0
    value = float(time_str)
    if unit == 'ms':
        return value
    elif unit == 's':
        value *= 1000
        return value
    elif unit == 'm':
        value *= 1000 * 60
        return value
    elif unit == 'h':
        value *= 1000 * 60 * 60
        return value
    elif unit == 'd':
        value *= 1000 * 60 * 60 * 24
    return value

def validate_time(timestr):
    time = 0.0
    result = re.match(time_regex, timestr)
    if result is not None:
        time = convert_time_string_to_milliseconds(result.group(1), result.group(2))
        return True, time
    return False, time

def print_error(*err : str, exit=False):
    print(Fore.RED + 'ERROR: ' + ' '.join(err) + Style.RESET_ALL, file=sys.stderr)
    if exit:
        sys.exit(1)

def print_warning(*err : str):
    print(Fore.YELLOW + 'WARNING: ' + ' '.join(err) + Style.RESET_ALL, file=sys.stderr)

def send_ethernet_packet(src, dst, eth_type, payload, interface, count=1, interval=1, verbose=False):
    ether_frame = Ether(src=src, dst=dst, type=eth_type) / Raw(load=payload)
    #sendp(ether_frame, iface=interface)
    _send(ether_frame, lambda iface: iface.l2socket(), iface=interface, inter=interval/1000, count=count, verbose=verbose)

def icmp_checksum(icmp_packet : ICMP):
    del icmp_packet.chksum
    icmp_packet = ICMP(bytes(icmp_packet))
    return bytes(icmp_packet)

def udp_checksum(udp_packet : UDP):
    del udp_packet.chksum
    udp_packet = UDP(bytes(udp_packet))
    return bytes(udp_packet)

def tcp_checksum(tcp_packet : TCP):
    del tcp_packet.chksum
    tcp_packet = TCP(bytes(tcp_packet))
    return bytes(tcp_packet)

def regenerate_icmp_seq(payload : bytes):
    icmp_packet = ICMP(payload)
    icmp_packet.seq = random.randint(1, 0x00fe)
    return icmp_checksum(icmp_packet)

def send_ethernet_packet_ip(src, dst, src_ip, dst_ip, ip_proto, payload, interface, count=1, interval=1, verbose=False):
    ip_packet_id = random.randint(1, 0x00fe)
    if ip_proto == ip_proto_icmp:
        payload = regenerate_icmp_seq(payload)
    elif ip_proto == ip_proto_udp:
        payload = udp_checksum(UDP(payload))
    ether_frame = Ether(src=src, dst=dst, type=ipv4_eth_type) / IP(src=src_ip, dst=dst_ip, proto=ip_proto, id=ip_packet_id) / Raw(load=payload)
    _send(ether_frame, lambda iface: iface.l2socket(), iface=interface, inter=interval/1000, count=count, verbose=verbose)
    ip_packet_id += 1

def send_ip_packet(src_ip, dst_ip, ip_proto, payload, count=1, interval=1, verbose=False):
    ip_packet_id = random.randint(1, 0x00fe)
    if ip_proto == ip_proto_icmp:
        payload = regenerate_icmp_seq(payload)
    elif ip_proto == ip_proto_udp:
        payload = udp_checksum(UDP(payload))
    packet = IP(src=src_ip, dst=dst_ip, proto=ip_proto, id=ip_packet_id) / Raw(load=payload)
    send(packet, inter=interval/1000, count=count, verbose=verbose)
    ip_packet_id += 1

def get_mac_address(interface_name):
    interfaces = get_windows_if_list()
    #print(json.dumps(interfaces, indent=4))
    for iface in interfaces:
        if any(iface[x] == interface_name for x in ['name', 'guid', 'description', 'index']):
            return iface['mac'], iface['ips']
    return None, None

def arp_scan(iface, ip, interval, count):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
    result, _ = srp(broadcast / arp_request, iface=iface, timeout=int(interval), retry=count, verbose=False)

    for sent, received in result:
        return True, str(received.hwsrc)
    return False, ''
    

args, parser = agruments()

interface = ''
src_mac_valid = False
src_mac = ''
dst_mac_valid = False
dst_mac = ''
src_ip_valid = False
src_ip = ''
dst_ip_valid = False
dst_ip = ''
ip_proto = 0
ip_proto_icmp = 1
ip_proto_udp = 17
ip_proto_tcp = 6
eth_type = 0x0800 # IPv4
goose_eth_type = 0x88b8  # GOOSE
ipv4_eth_type = 0x0800
ipv4_eth_type_hex = hex(ipv4_eth_type)
eth_str = ''
eth_type_valid = False
payload_str = ''
payload_valid = False
payload_file = ''
payload_file_valid = False
count = 1
interval = 1
interval_str = ''
interval_valid = True
verbose=False
arp = False
tcp_server = False
tcp_port_str = ''
tcp_port = 0
tcp_port_valid = False
udp_server = False
udp_port_str = ''
udp_port = 0
udp_port_valid = False

for opt, arg in vars(args).items():
    if opt in ('arp') and arg is not None:
        arp = arg
    if opt in ('tcp_server') and arg is not None:
        tcp_port_str = arg
        tcp_server = True
        tcp_port_valid, tcp_port = validate_port(arg)
    if opt in ('udp_server') and arg is not None:
        udp_port_str = arg
        udp_server = True
        udp_port_valid, udp_port = validate_port(arg)
    if opt in ('interface') and arg is not None:
        interface = arg
    if opt in ('src_mac') and arg is not None:
        src_mac_valid, src_mac = validate_mac(arg)
    if opt in ('dst_mac') and arg is not None:
        dst_mac_valid, dst_mac = validate_mac(arg)
    if opt in ('ether_type') and arg is not None:
        eth_str = arg
        eth_type_valid, eth_type = validate_ether_type(arg)
    if opt in ('src_ip') and arg is not None:
        src_ip_valid, src_ip = validate_ip(arg)
    if opt in ('dst_ip') and arg is not None:
        dst_ip_valid, dst_ip = validate_ip(arg)
    if opt in ('ip_proto') and arg is not None:
        ip_proto = arg
    if opt in ('payload') and arg is not None:
        payload_valid, payload_str = validate_payload(arg)
    if opt in ('payload_file') and arg is not None:
        payload_file = arg
        payload_file_valid, payload_valid, payload_str = validate_payload_paload_file(payload_file)
    if opt in ('packet_count') and arg is not None:
        count = arg
    if opt in ('packet_interval') and arg is not None:
        interval_str = arg
        interval_valid , interval = validate_time(arg)
    if opt in ('verbose') and arg is not None:
        verbose=arg

if src_mac == '':
    src_mac, ips = get_mac_address(interface)
    if src_mac == None:
        print_error(f'Invalid interface: {interface}', exit=True)
    src_mac_valid = True

if not src_mac_valid:
    print_error(f'Invalid Source MAC address: {src_mac}', exit=True)

if interval_str != '' and not interval_valid:
    print_error(f'Invalid packet interval: {interval_str}', exit=True)

if not arp:
    if dst_mac == '' and dst_ip == '':
        parser.error(f'At-least one of the destination MAC or IPv4 address is required.')
    if dst_mac == '' and dst_ip_valid:
        if dst_ip == src_ip:
            dst_mac = src_mac
            dst_mac_valid = True
        else:
            if verbose:
                print(f'Sending Arp to {dst_ip} using interface {interface}, timeout time=1s, retry count={count}')
            dst_mac_valid, dst_mac = arp_scan(interface, dst_ip, 1, count)
        if dst_mac_valid and verbose:
            print(f'Found mac address {dst_mac} for ip address {dst_ip}')
        if not dst_mac_valid:
            print_error(f'Could not find MAC address for {dst_ip}', exit=True)
    if dst_mac == '':
        print_error(f'Could not resolve MAC address for {dst_ip}', exit=True)
    if not dst_mac_valid:
        print_error(f'Invalid Destination MAC address: {dst_mac}', exit=True)

    if not eth_type_valid:
        print_error(f'Invalid ether type: {eth_str}', exit=True)

    if eth_type == ipv4_eth_type:
        if src_ip == '':
            parser.error(f'Source IPv4 address is required for ether type {ipv4_eth_type_hex}')
        elif src_mac == '' and ips is not None and src_ip not in ips:
            print_warning(f'Source Address {src_ip} is not confgured on interface {interface}')
        if ip_proto == 0:
            parser.error(f'IPv4 protocol type is required for ether type {ipv4_eth_type_hex}')

    if payload_file != '' and not payload_file_valid:
        print_error(f'Invalid payload file : {payload_file}', exit=True)

    if not payload_valid:
        print_error(f'Invalid payload hex stream: {payload_str}', exit=True)

if arp:
    if dst_ip == '':
        parser.error('For ARP request destination IP address is required.')
    print(f'Sending Arp to {dst_ip} using interface {interface}, timeout time={interval/1000}s, retry count={count}')
    found, mac = arp_scan(interface, dst_ip, interval/1000, count)
    if found:
        print(f'Found mac address {mac} for ip address {dst_ip}')
    else:
        print(f'Could not find mac address for ip address {dst_ip}')
    sys.exit(0)

payload = bytes.fromhex(payload_str)

if eth_type == ipv4_eth_type:
    if ip_proto == ip_proto_tcp:
        print_error('TCP packet not yet supported.')
        sys.exit(1)
    if src_ip == dst_ip:
        send_ip_packet(src_ip, dst_ip, ip_proto, payload, count, interval, verbose)
    else:
        send_ethernet_packet_ip(src_mac, dst_mac, src_ip, dst_ip, ip_proto, payload, interface, count, interval, verbose)
else:
    send_ethernet_packet(src_mac, dst_mac, eth_type, payload, interface, count, interval, verbose)
