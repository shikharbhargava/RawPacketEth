# MIT License
# This file is part of Raw Ethernet Packet Generator
# See https://github.com/shikharbhargava/raw-packet-eth-win for more information
# Copyright (C) Shikhar Bhargava

"""
This file contains implementation of a TCP Server
"""

import socket
import signal
import select
import sys

class TCPServer:
    """
    Class to configure and start TCP server
    """
    _address = ""
    _port = -1
    _server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _sockets = []

    def address(self):
        """
        Returns bound server address
        """
        return self._address

    def port(self):
        """
        Returns bound server port
        """
        return self._port

    def server_socket(self):
        """
        Returns server socket
        """
        return self._server_socket

    def all_socket(self):
        """
        Returns all sockets including server and all connected client sockets
        """
        return self._sockets

    def __init__(self, address:str, port:int):
        self._address = address
        self._port = port
        self._server_socket.bind((self._address, self._port))
        self._server_socket.listen(5)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sockets = [self._server_socket]

    def start(self, verbose:bool=False):
        """
        Starts TCP server
        """
        if verbose:
            print('Server strated...')
            print(f'Address:{self._address}, port:{self._port}')
        while True:
            try:
                readable, _, _ = select.select(self._sockets, [], [], 1)
                for s in readable:
                    if s is self._server_socket:
                        client_socket, addr = self._server_socket.accept()
                        print(f"[*] Accepted connection from {addr}")
                        client_socket.setblocking(0)
                        self._sockets.append(client_socket)
                    else:
                        data = s.recv(1024)
                        if data:
                            print(f"Received: {data.decode('utf-8')}")
                        else:
                            print(f"Closing connection from: {s.getpeername()}")
                            s.close()
                            self._sockets.remove(s)
            except OSError:
                break

if __name__ == "__main__":
    server = TCPServer("0.0.0.0", 9999)

    def signal_handler(*_):
        """
        Signal handler
        """
        print('Shutting down server...')
        server_socket = server.server_socket()
        for s in server.all_socket():
            if s is not server_socket:
                try:
                    print(f"Disconnecting from {s.getpeername()}..")
                    s.close()
                except OSError:
                    pass
        sys.exit(0)


    signal.signal(signal.SIGINT, signal_handler)
    server.start(verbose=True)
