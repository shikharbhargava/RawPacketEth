import socket
import time

def tcp_client(host='127.0.0.1', port=9999, message='Hello, Server!\n'):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((host, port))
        for i in range(1, 100):
            client_socket.sendall(message.encode('utf-8'))
            time.sleep(1)
    except ConnectionRefusedError:
        print(f"Could not connect to {host, port}")
    except ConnectionResetError:
        print(f"Connection resetted for {host, port}")
    client_socket.close()

if __name__ == "__main__":
    tcp_client()
