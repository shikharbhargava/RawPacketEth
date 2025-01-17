# MIT License
# This file is part of Raw Ethernet Packet Generator
# See https://github.com/shikharbhargava/raw-packet-eth-win for more information
# Copyright (C) Shikhar Bhargava

"""
This file contains maps for ethernet protocol type and IP protocol type
"""

__EtherType = dict({
    0x0800 : {'name' : 'Internet Protocol version 4', 'abb' : 'IPv4'},
    0x0806 : {'name' : 'Address Resolution Protocol', 'abb' : 'ARP'},
    0x0842 : {'name' : 'Wake-on-LAN', 'abb' : 'WOL'},
    0x2000 : {'name' : 'Cisco Discovery Protocol', 'abb' : 'CDP'},
    0x22EA : {'name' : 'Stream Reservation Protocol', 'abb' : 'SRP'},
    0x22F0 : {'name' : 'Audio Video Transport Protocol', 'abb' : 'AVTP'},
    0x22F3 : {'name' : 'Transparent Interconnection of Lots of Links', 'abb' : 'TRILL '},
    0x6002 : {'name' : 'DEC MOP RC', 'abb' : 'MOP'},
    0x6003 : {'name' : 'DECnet Phase IV - DNA Routing', 'abb' : 'DECnet'},
    0x6004 : {'name' : 'DEC LAT', 'abb' : 'LAT'},
    0x8035 : {'name' : 'Reverse Address Resolution Protocol', 'abb' : 'RARP'},
    0x809B : {'name' : 'AppleTalk', 'abb' : 'EtherTalk'},
    0x80F3 : {'name' : 'AppleTalk Address Resolution Protocol', 'abb' : 'AARP'},
    0x8100 : {'name' : 'VLAN-tagged frame', 'abb' : 'IEEE 802.1Q'},
    0x8102 : {'name' : 'Simple Loop Prevention Protocol', 'abb' : 'SLPP'},
    0x8103 : {'name' : 'Virtual Link Aggregation Control Protocol', 'abb' : 'VLACP'},
    0x8137 : {'name' : 'Internetwork Packet Exchange', 'abb' : 'IPX'},
    0x8204 : {'name' : 'QNX Qnet', 'abb' : 'QNX'},
    0x86DD : {'name' : 'Internet Protocol Version 6', 'abb' : 'IPv6'},
    0x8808 : {'name' : 'Ethernet flow control', 'abb' : ''},
    0x8809 : {'name' : 'Link Aggregation Control Protocol', 'abb' : 'LACP'},
    0x8819 : {'name' : 'CobraNet', 'abb' : ''},
    0x8847 : {'name' : 'Multiprotocol Label Switching unicast', 'abb' : 'MPLS-U'},
    0x8848 : {'name' : 'Multiprotocol Label Switching multicast', 'abb' : 'MPLS-M'},
    0x8863 : {'name' : 'Point-to-Point Protocol over Ethernet Discovery Stage', 'abb' : 'PPPoE-DS'},
    0x8864 : {'name' : 'Point-to-Point Protocol over Ethernet Session Stage', 'abb' : 'PPPoE-SS'},
    0x887B : {'name' : 'HomePlug 1.0 MME', 'abb' : 'HomePlug'},
    0x888E : {'name' : 'EAP over LAN', 'abb' : 'IEEE 802.1X'},
    0x8892 : {'name' : 'PROFINET Protocol', 'abb' : 'PROFINET'},
    0x889A : {'name' : 'SCSI over Ethernet', 'abb' : 'HyperSCSI'},
    0x88A2 : {'name' : 'ATA over Ethernet', 'abb' : 'AoE'},
    0x88A4 : {'name' : 'EtherCAT Protocol', 'abb' : 'EtherCAT'},
    0x88A8 : {'name' : 'Service VLAN tag identifier S-Tag on Q-in-Q tunnel', 'abb' : 'QinQ'},
    0x88AB : {'name' : 'Ethernet Powerlink', 'abb' : ''},
    0x88B8 : {'name' : 'Generic Object Oriented Substation event', 'abb' : 'GOOSE'},
    0x88B9 : {'name' : 'Generic Substation Events', 'abb' : 'GSE'},
    0x88BA : {'name' : 'Sampled Value Transmission', 'abb' : 'SV'},
    0x88CC : {'name' : 'Link Layer Discovery Protocol', 'abb' : 'LLDP'},
    0x88CD : {'name' : 'SERCOS III', 'abb' : ''},
    0x88E1 : {'name' : 'HomePlug Green PHY', 'abb' : ''},
    0x88E3 : {'name' : 'Media Redundancy Protocol', 'abb' : 'IEC62439-2'},
    0x88E5 : {'name' : 'IEEE 802.1AE MAC security', 'abb' : 'MACsec'},
    0x88E7 : {'name' : 'Provider Backbone Bridges', 'abb' : 'IEEE 802.1ah'},
    0x88F7 : {'name' : 'Precision Time Protocol', 'abb' : 'PTP'},
    0x88F8 : {'name' : 'NC-SI', 'abb' : ''},
    0x88FB : {'name' : 'Parallel Redundancy Protocol', 'abb' : 'PRP'},
    0x8902 : {'name' : 'IEEE 802.1ag Connectivity Fault Management', 'abb' : 'CFM'},
    0x8906 : {'name' : 'Fibre Channel over Ethernet', 'abb' : 'FCoE'},
    0x8914 : {'name' : 'Fibre Channel over Ethernet Initialization Protocol', 'abb' : 'FCoE'},
    0x8915 : {'name' : 'RDMA over Converged Ethernet', 'abb' : 'RoCE'},
    0x891D : {'name' : 'TTEthernet Protocol Control Frame', 'abb' : 'TTE'},
    0x893a : {'name' : '1905.1 IEEE Protocol', 'abb' : '1905.1'},
    0x892F : {'name' : 'High-availability Seamless Redundancy', 'abb' : 'HSR'},
    0x9000 : {'name' : 'Ethernet Configuration Testing Protocol', 'abb' : 'CTP'},
    0xF1C1 : {'name' : 'Time-Sensitive Networking', 'abb' : 'TSN'}
})

def PrintEtherType():
    index_len = 8
    name_len = 100
    abb_len = 20
    number_len = 10
    print(f'{"Index":<{index_len}}{"Ether Type Name":<{name_len}}{"Abbreviation":<{abb_len}}{"Number":<{number_len}}')
    print(f'{"-"*index_len}{"-"*name_len}{"-"*abb_len}{"-"*number_len}')
    i = 1
    for k, v in __EtherType.items():
        name  = v['name']
        abb   = v['abb']
        value = hex(k)
        print(f'{i:<{index_len}}{name:<{name_len}}{abb:<{abb_len}}{value:<{number_len}}')
        i += 1

def EtherProtoName(number : int):
    return __EtherType[number]['name']

def EtherProtoNameAbbrevation(number : int):
    return __EtherType[number]['abb']

def EtherProtoNumber(name : str):
    name = name.lower()
    for value, names in __EtherType.items():
        if names['name'].lower() == name:
            return True, value
        if names['abb'].lower() == name:
            return True, value
    return False, None

__IPProto = dict({
    0x00 : {'name' : 'IPv6 Hop-by-Hop Option', 'abb' : 'HOPOPT'},
    0x01 : {'name' : 'Internet Control Message Protocol', 'abb' : 'ICMP'},
    0x02 : {'name' : 'Internet Group Management Protocol', 'abb' : 'IGMP'},
    0x03 : {'name' : 'Gateway-to-Gateway Protocol', 'abb' : 'GGP'},
    0x04 : {'name' : 'IP in IP (encapsulation)', 'abb' : 'IP-in-IP'},
    0x05 : {'name' : 'Internet Stream Protocol', 'abb' : 'ST'},
    0x06 : {'name' : 'Transmission Control Protocol', 'abb' : 'TCP'},
    0x07 : {'name' : 'Core-based trees', 'abb' : 'CBT'},
    0x08 : {'name' : 'Exterior Gateway Protocol', 'abb' : 'EGP'},
    0x09 : {'name' : 'Interior gateway protocol', 'abb' : 'IGP'},
    0x0A : {'name' : 'BBN RCC Monitoring', 'abb' : 'BBN-RCC-MON'},
    0x0B : {'name' : 'Network Voice Protocol', 'abb' : 'NVP-II'},
    0x0C : {'name' : 'Xerox PUP', 'abb' : 'PUP'},
    0x0D : {'name' : 'ARGUS', 'abb' : 'ARGUS'},
    0x0E : {'name' : 'EMCON', 'abb' : 'EMCON'},
    0x0F : {'name' : 'Cross Net Debugger', 'abb' : 'XNET'},
    0x10 : {'name' : 'Chaos', 'abb' : 'CHAOS'},
    0x11 : {'name' : 'User Datagram Protocol', 'abb' : 'UDP'},
    0x12 : {'name' : 'Multiplexing', 'abb' : 'MUX'},
    0x13 : {'name' : 'DCN Measurement Subsystems', 'abb' : 'DCN-MEAS'},
    0x14 : {'name' : 'Host Monitoring Protocol', 'abb' : 'HMP'},
    0x15 : {'name' : 'Packet Radio Measurement', 'abb' : 'PRM'},
    0x16 : {'name' : 'XEROX NS IDP', 'abb' : 'XNS-IDP'},
    0x17 : {'name' : 'Trunk-1', 'abb' : 'TRUNK-1'},
    0x18 : {'name' : 'Trunk-2', 'abb' : 'TRUNK-2'},
    0x19 : {'name' : 'Leaf-1', 'abb' : 'LEAF-1'},
    0x1A : {'name' : 'Leaf-2', 'abb' : 'LEAF-2'},
    0x1B : {'name' : 'Reliable Data Protocol', 'abb' : 'RDP'},
    0x1C : {'name' : 'Internet Reliable Transaction Protocol', 'abb' : 'IRTP'},
    0x1D : {'name' : 'ISO Transport Protocol Class 4', 'abb' : 'ISO-TP4'},
    0x1E : {'name' : 'Bulk Data Transfer Protocol', 'abb' : 'NETBLT'},
    0x1F : {'name' : 'MFE Network Services Protocol', 'abb' : 'MFE-NSP'},
    0x20 : {'name' : 'MERIT Internodal Protocol', 'abb' : 'MERIT-INP'},
    0x21 : {'name' : 'Datagram Congestion Control Protocol', 'abb' : 'DCCP'},
    0x22 : {'name' : 'Third Party Connect Protocol', 'abb' : '3PC'},
    0x23 : {'name' : 'Inter-Domain Policy Routing Protocol', 'abb' : 'IDPR'},
    0x24 : {'name' : 'Xpress Transport Protocol', 'abb' : 'XTP'},
    0x25 : {'name' : 'Datagram Delivery Protocol', 'abb' : 'DDP'},
    0x26 : {'name' : 'IDPR Control Message Transport Protocol', 'abb' : 'IDPR-CMTP'},
    0x27 : {'name' : 'TP++ Transport Protocol', 'abb' : 'TP++'},
    0x28 : {'name' : 'IL Transport Protocol', 'abb' : 'IL'},
    0x29 : {'name' : 'IPv6 Encapsulation (6to4 and 6in4)', 'abb' : 'IPv6'},
    0x2A : {'name' : 'Source Demand Routing Protocol', 'abb' : 'SDRP'},
    0x2B : {'name' : 'Routing Header for IPv6', 'abb' : 'IPv6-Route'},
    0x2C : {'name' : 'Fragment Header for IPv6', 'abb' : 'IPv6-Frag'},
    0x2D : {'name' : 'Inter-Domain Routing Protocol', 'abb' : 'IDRP'},
    0x2E : {'name' : 'Resource Reservation Protocol', 'abb' : 'RSVP'},
    0x2F : {'name' : 'Generic Routing Encapsulation', 'abb' : 'GRE'},
    0x30 : {'name' : 'Dynamic Source Routing Protocol', 'abb' : 'DSR'},
    0x31 : {'name' : 'Burroughs Network Architecture', 'abb' : 'BNA'},
    0x32 : {'name' : 'Encapsulating Security Payload', 'abb' : 'ESP'},
    0x33 : {'name' : 'Authentication Header', 'abb' : 'AH'},
    0x34 : {'name' : 'Integrated Net Layer Security Protocol', 'abb' : 'I-NLSP'},
    0x35 : {'name' : 'SwIPe', 'abb' : 'SwIPe'},
    0x36 : {'name' : 'NBMA Address Resolution Protocol', 'abb' : 'NARP'},
    0x37 : {'name' : 'IP Mobility (Min Encap)', 'abb' : 'MOBILE'},
    0x38 : {'name' : 'Transport Layer Security Protocol', 'abb' : 'TLSP'},
    0x39 : {'name' : 'Simple Key-Management for Internet Protocol', 'abb' : 'SKIP'},
    0x3A : {'name' : 'ICMP for IPv6', 'abb' : 'IPv6-ICMP'},
    0x3B : {'name' : 'No Next Header for IPv6', 'abb' : 'IPv6-NoNxt'},
    0x3C : {'name' : 'Destination Options for IPv6', 'abb' : 'IPv6-Opts'},
    0x3D : {'name' : 'Any host internal protocol', 'abb' : ''},
    0x3E : {'name' : 'CFTP', 'abb' : 'CFTP'},
    0x3F : {'name' : 'Any local network', 'abb' : ''},
    0x40 : {'name' : 'SATNET and Backroom EXPAK', 'abb' : 'SAT-EXPAK'},
    0x41 : {'name' : 'Kryptolan', 'abb' : 'KRYPTOLAN'},
    0x42 : {'name' : 'MIT Remote Virtual Disk Protocol', 'abb' : 'RVD'},
    0x43 : {'name' : 'Internet Pluribus Packet Core', 'abb' : 'IPPC'},
    0x44 : {'name' : 'Any distributed file system', 'abb' : ''},
    0x45 : {'name' : 'SATNET Monitoring', 'abb' : 'SAT-MON'},
    0x46 : {'name' : 'VISA Protocol', 'abb' : 'VISA'},
    0x47 : {'name' : 'Internet Packet Core Utility', 'abb' : 'IPCU'},
    0x48 : {'name' : 'Computer Protocol Network Executive', 'abb' : 'CPNX'},
    0x49 : {'name' : 'Computer Protocol Heart Beat', 'abb' : 'CPHB'},
    0x4A : {'name' : 'Wang Span Network', 'abb' : 'WSN'},
    0x4B : {'name' : 'Packet Video Protocol', 'abb' : 'PVP'},
    0x4C : {'name' : 'Backroom SATNET Monitoring', 'abb' : 'BR-SAT-MON'},
    0x4D : {'name' : 'SUN ND PROTOCOL-Temporary', 'abb' : 'SUN-ND'},
    0x4E : {'name' : 'WIDEBAND Monitoring', 'abb' : 'WB-MON'},
    0x4F : {'name' : 'WIDEBAND EXPAK', 'abb' : 'WB-EXPAK'},
    0x50 : {'name' : 'International Organization for Standardization Internet Protocol', 'abb' : 'ISO-IP'},
    0x51 : {'name' : 'Versatile Message Transaction Protocol', 'abb' : 'VMTP'},
    0x52 : {'name' : 'Secure Versatile Message Transaction Protocol', 'abb' : 'SECURE-VMTP'},
    0x53 : {'name' : 'VINES', 'abb' : 'VINES'},
    0x54 : {'name' : 'Transaction Transport Protocol', 'abb' : 'TTP'},
    0x54 : {'name' : 'Internet Protocol Traffic Manager', 'abb' : 'IPTM'},
    0x55 : {'name' : 'NSFNET-IGP', 'abb' : 'NSFNET-IGP'},
    0x56 : {'name' : 'Dissimilar Gateway Protocol', 'abb' : 'DGP'},
    0x57 : {'name' : 'TCF', 'abb' : 'TCF'},
    0x58 : {'name' : 'EIGRP', 'abb' : 'EIGRP'},
    0x59 : {'name' : 'Open Shortest Path First', 'abb' : 'OSPF'},
    0x5A : {'name' : 'Sprite RPC Protocol', 'abb' : 'Sprite-RPC'},
    0x5B : {'name' : 'Locus Address Resolution Protocol', 'abb' : 'LARP'},
    0x5C : {'name' : 'Multicast Transport Protocol', 'abb' : 'MTP'},
    0x5D : {'name' : 'AX.25', 'abb' : 'AX.25'},
    0x5E : {'name' : 'KA9Q NOS compatible IP over IP tunneling', 'abb' : 'OS'},
    0x5F : {'name' : 'Mobile Internetworking Control Protocol', 'abb' : 'MICP'},
    0x60 : {'name' : 'Semaphore Communications Sec. Pro', 'abb' : 'SCC-SP'},
    0x61 : {'name' : 'Ethernet-within-IP Encapsulation', 'abb' : 'ETHERIP'},
    0x62 : {'name' : 'Encapsulation Header', 'abb' : 'ENCAP'},
    0x63 : {'name' : 'Any private encryption scheme', 'abb' : ''},
    0x64 : {'name' : 'GMTP', 'abb' : 'GMTP'},
    0x65 : {'name' : 'Ipsilon Flow Management Protocol', 'abb' : 'IFMP'},
    0x66 : {'name' : 'PNNI over IP', 'abb' : 'PNNI'},
    0x67 : {'name' : 'Protocol Independent Multicast', 'abb' : 'PIM'},
    0x68 : {'name' : 'Aggregate Route IP Switching Protocol', 'abb' : 'ARIS'},
    0x69 : {'name' : 'Space Communications Protocol Standards', 'abb' : 'SCPS'},
    0x6A : {'name' : 'QNX', 'abb' : 'QNX'},
    0x6B : {'name' : 'Active Networks', 'abb' : 'A/N'},
    0x6C : {'name' : 'IP Payload Compression Protocol', 'abb' : 'IPComp'},
    0x6D : {'name' : 'Sitara Networks Protocol', 'abb' : 'SNP'},
    0x6E : {'name' : 'Compaq Peer Protocol', 'abb' : 'Compaq-Peer'},
    0x6F : {'name' : 'IPX in IP', 'abb' : 'IPX-in-IP'},
    0x70 : {'name' : 'Virtual Router Redundancy Protocol, Common Address Redundancy Protocol', 'abb' : 'VRRP'},
    0x71 : {'name' : 'PGM Reliable Transport Protocol', 'abb' : 'PGM'},
    0x72 : {'name' : 'Any 0-hop protocol', 'abb' : ''},
    0x73 : {'name' : 'Layer Two Tunneling Protocol Version 3', 'abb' : 'L2TP'},
    0x74 : {'name' : 'D-II Data Exchange', 'abb' : 'DDX'},
    0x75 : {'name' : 'Interactive Agent Transfer Protocol', 'abb' : 'IATP'},
    0x76 : {'name' : 'Schedule Transfer Protocol', 'abb' : 'STP'},
    0x77 : {'name' : 'SpectraLink Radio Protocol', 'abb' : 'SRP'},
    0x78 : {'name' : 'Universal Transport Interface Protocol', 'abb' : 'UTI'},
    0x79 : {'name' : 'Simple Message Protocol', 'abb' : 'SMP'},
    0x7A : {'name' : 'Simple Multicast Protocol', 'abb' : 'SM'},
    0x7B : {'name' : 'Performance Transparency Protocol', 'abb' : 'PTP'},
    0x7C : {'name' : 'Intermediate System to Intermediate System Protocol over IPv4', 'abb' : 'IS-IS over IPv4'},
    0x7D : {'name' : 'Flexible Intra-AS Routing Environment', 'abb' : 'FIRE'},
    0x7E : {'name' : 'Combat Radio Transport Protocol', 'abb' : 'CRTP'},
    0x7F : {'name' : 'Combat Radio User Datagram', 'abb' : 'CRUDP'},
    0x80 : {'name' : 'Service-Specific Connection-Oriented Protocol in a Multilink and Connectionless Environment', 'abb' : 'SSCOPMCE'},
    0x81 : {'name' : 'IPLT', 'abb' : 'IPLT'},
    0x82 : {'name' : 'Secure Packet Shield', 'abb' : 'SPS'},
    0x83 : {'name' : 'Private IP Encapsulation within IP', 'abb' : 'PIPE'},
    0x84 : {'name' : 'Stream Control Transmission Protocol', 'abb' : 'SCTP'},
    0x85 : {'name' : 'Fibre Channel', 'abb' : 'FC'},
    0x86 : {'name' : 'Reservation Protocol End-to-End Ignore', 'abb' : 'RSVP-E2E-IGNORE'},
    0x87 : {'name' : 'Mobility Extension Header for IPv6', 'abb' : 'Mobility Header'},
    0x88 : {'name' : 'Lightweight User Datagram Protocol', 'abb' : 'UDPLite'},
    0x89 : {'name' : 'Multiprotocol Label Switching Encapsulated in IP', 'abb' : 'MPLS-in-IP'},
    0x8A : {'name' : 'MANET Protocols', 'abb' : 'manet'},
    0x8B : {'name' : 'Host Identity Protocol', 'abb' : 'HIP'},
    0x8C : {'name' : 'Site Multihoming by IPv6 Intermediation', 'abb' : 'Shim6'},
    0x8D : {'name' : 'Wrapped Encapsulating Security Payload', 'abb' : 'WESP'},
    0x8E : {'name' : 'Robust Header Compression', 'abb' : 'ROHC'},
    0x8F : {'name' : 'Segment Routing over IPv6', 'abb' : 'Ethernet'},
    0x90 : {'name' : 'AGGFRAG Encapsulation Payload for ESP', 'abb' : 'AGGFRAG'},
    0x91 : {'name' : 'Network Service Header', 'abb' : 'NSH'},
})

def PrintIpProtocolType():
    index_len = 8
    name_len = 100
    abb_len = 20
    number_len = 10
    print(f'{"Index":<{index_len}}{"IP Protocol Name":<{name_len}}{"Abbreviation":<{abb_len}}{"Number":<{number_len}}')
    print(f'{"-"*index_len}{"-"*name_len}{"-"*abb_len}{"-"*number_len}')
    i = 1
    for k, v in __IPProto.items():
        name  = v['name']
        abb   = v['abb']
        value = hex(k)
        print(f'{i:<{index_len}}{name:<{name_len}}{abb:<{abb_len}}{value:<{number_len}}')
        i += 1


def IPProtoName(number : int):
    return __IPProto[number]['name']

def IPProtoNameAbbrevation(number : int):
    return __IPProto[number]['abb']

def IPProtoNumber(name : str):
    name = name.lower()
    for value, names in __IPProto.items():
        if names['name'].lower() == name:
            return True, value
        if names['abb'].lower() == name:
            return True, value
    return False, -1
