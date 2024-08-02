import socket
import signal
import sys

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    try:
        print(f"Disconnecting from {client_socket.getpeername()}..")
        client_socket.close()
    except OSError:
        pass
    sys.exit(0)

def udp_client(host='127.0.0.1', port=9999, message='Hello, Server!\n'):
    try:
        client_socket.sendto(message.encode(), (host, port))
    except socket.timeout:
        print("Request timed out. Server did not respond.")
    except ConnectionRefusedError:
        print(f"Could not connect to {host, port}")
    except ConnectionResetError:
        print(f"Connection resetted for {host, port}")
    finally:
        # Close the socket
        client_socket.close()

if __name__ == "__main__":
    udp_client()
