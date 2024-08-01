import argparse, sys

parser = argparse.ArgumentParser(description='Sends raw packets on an interface.')
parser.add_argument('-v', '--verbose', action='store_true', help='Show output log')
parser.add_argument('-a', '--arp', action='store_true', help='Resolve mac address for an IPv4 address by sending ARP requests, use'
                                ' -i option for selecting interface, -D option for destination address,'
                                ' -c option for count and -I option for interval')
parser.add_argument('-i', '--interface', metavar='INTERFACE-NAME', required=True, help='Interface Name')
parser.add_argument('-s','--src_mac', metavar='SRC-MAC', help='Source MAC Address. Optional, if not provided then mac address of the itherface will be used')
parser.add_argument('-d', '--dst_mac', metavar='DST-MAC', help='destination mac address, required')
parser.add_argument('-e', '--ether_type', metavar='ETHER-TYPE', help='ethernet type in hex, required')
parser.add_argument('-S', '--src_ip', metavar='SRC-IP', help='source ipv4 address, required if ethernet type is 0x0800 (ipv4)')
parser.add_argument('-D', '--dst_ip', metavar='DST-IP', help='destination ipv4 address, required if ethernet type is 0x0800 (ipv4)')
parser.add_argument('-p', '--payload', metavar='PAYLOAD', help='packet payload in hex stream')
parser.add_argument('-f', '--payload_file', metavar='PAYLOAD-FILE', help='packet payload file in hex stream')
parser.add_argument('-c', '--packet_count', metavar='PACKET-COUNT', help='number of packet to be sent [default=1]')
parser.add_argument('-I', '--packet_interval', metavar='PACKET-INTERVAL', help='time delay between 2 consecutive packets [default=1s, minimum=1ms, supported units={ms,s,m,h,d}]')

# parse arguments
args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

for arg_name, arg_value in vars(args).items():
    print(f"Argument {arg_name}: {arg_value}")

# use your args
print("arp {}".format(args.arp))
print("interface {}".format(args.interface))