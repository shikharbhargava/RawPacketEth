import socket
import signal
import select
import sys

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sockets = [server_socket]

def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    sys.exit(0)

def udp_server(host='0.0.0.0', port=4713):
    server_socket.bind((host, port))
    print(f"[*] Listening on {host}:{port}")

    while True:
        readable, _, _ = select.select(sockets, [], [], 1)
        for s in readable:
            data, addr = server_socket.recvfrom(1024)
            if data:
                print(f"Received from {addr}: {data.hex()}, ASCII: {data.decode('utf-8')}")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    udp_server()
