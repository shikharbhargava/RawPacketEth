import socket
import signal
import select
import sys

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(("0.0.0.0", 9999))
server_socket.listen(5)
sockets = [server_socket]

def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    for s in sockets:
        if s is not server_socket:
            try:
                print(f"Disconnecting from {s.getpeername()}..")
                s.close()
            except OSError:
                pass
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    while True:
        try:
            readable, _, _ = select.select(sockets, [], [], 1)
            for s in readable:
                if s is server_socket:
                    client_socket, addr = server_socket.accept()
                    print(f"[*] Accepted connection from {addr}")
                    client_socket.setblocking(0)
                    sockets.append(client_socket)
                else:
                    data = s.recv(1024)
                    if data:
                        print(f"Received: {data.decode('utf-8')}")
                    else:
                        print(f"Closing connection from: {s.getpeername()}")
                        s.close()
                        sockets.remove(s)
        except OSError:
            break

if __name__ == "__main__":
    main()
