from socket import socket, AF_PACKET, SOCK_RAW

def send_ethernet_packet(src, dst, eth_type, payload, interface="eth0"):
    assert len(src) == len(dst) == 6  # 48-bit Ethernet addresses
    assert len(eth_type) == 2  # 16-bit Ethernet type

    s = socket(AF_PACKET, SOCK_RAW)
    s.bind((interface, 0))  # Bind to the specified interface

    # Construct the Ethernet frame
    ethernet_frame = src + dst + eth_type + payload

    # Send the raw Ethernet frame
    s.send(ethernet_frame)

# Example usage
src_mac = b'\x00\x11\x22\x33\x44\x55'
dst_mac = b'\x66\x77\x88\x99\xaa\xbb'
eth_type = b'\x08\x00'  # IPv4
payload = b'Hello, world!'

send_ethernet_packet(src_mac, dst_mac, eth_type, payload)
