import os
import re
import sys
import textwrap

from argparse import ArgumentParser
from colorama import Fore, Style
from print import print_error, print_warning

OPTIONS_REGEX = r'(((-){1,2}[a-z_]+)|((-){1,2}[A-Z]))([ \,\]])(([A-Z\-]+){0,1})'
ALL_OPTIONS_REGEX = r'(((-){1}[a-z_]+)|((-){1,2}[A-Z]))([ \,])(([A-Z\-]+){0,1}), ((-){2}[a-z_]+)([ \,])(([A-Z\-]+){0,1})'
TAB_CORRECTION_REGEX = r'(.+)([a-zA-Z])([\n]*   +)(.+)'
USEAGE_REGEX = r'(usage:.+)((\n)( +)(.+))+'

class ArgParser(ArgumentParser):
    
    prog_name = os.path.splitext(sys.argv[0])[0]
    prog_version = '1.0'

    def __find_max_line_length(self, paragraph):
        lines = paragraph.split('\n')
        max_length = max(len(line) for line in lines)
        return max_length

    def __split_string_with_textwrap(self, input_str, max_length):
        return textwrap.wrap(input_str, width=max_length)

    def error(self, message):
        print_error(f'{message}')
        self.print_help()
        sys.exit(1)

    def _print_message(self, message, file=None):
        if message:
            if message.startswith('usage'):
                max_length = self.__find_max_line_length(message)
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
                    replace_list = self.__split_string_with_textwrap(replace_str, max_length)
                    replace_str = replace_list[0]
                    for i in range(1, len(replace_list)):
                        next_line = ' ' * colmn_size + replace_list[i]
                        new_replace_list = self.__split_string_with_textwrap(next_line, max_length)
                        next_line = new_replace_list[0]
                        for j in range(1, len(new_replace_list)):
                            next_line = next_line + '\n' + ' ' * colmn_size + new_replace_list[j]
                        replace_str = replace_str + '\n' + next_line
                    message = message.replace(''.join(r[0:]), replace_str)
                message = re.sub(OPTIONS_REGEX, fr'{Fore.YELLOW}\1{Style.RESET_ALL}\6{Fore.GREEN}\7{Style.RESET_ALL}', message)
                message = (f'{Fore.YELLOW}program{Style.RESET_ALL}:'
                           f' {Fore.CYAN}{self.prog_name} {Fore.YELLOW}version{Style.RESET_ALL}:'
                           f' {Fore.CYAN}{self.prog_version}{Style.RESET_ALL}\n\n{message}')
                message = message.replace('usage', f'{Fore.YELLOW}usage{Style.RESET_ALL}')
                message = message.replace('options', f'{Fore.YELLOW}options{Style.RESET_ALL}')
                message = message.replace(self.prog, f'{Fore.CYAN}{self.prog}{Style.RESET_ALL}')
            print(message)
    def __init__(self, program=os.path.splitext(sys.argv[0])[0], version="1.0", *args, **kwargs):
        super(ArgumentParser, self).__init__(*args, **kwargs)
        self.prog_name = program
        self.prog_version = version

def ParseArguments(arguments:list):
    parser = ArgParser(description='Sends raw packets on an interface.')
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

    args = parser.parse_args(args=None if arguments[1:] else ['--help'])
    return args, parser
