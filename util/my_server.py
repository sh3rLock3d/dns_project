import socket
import threading
import time
import pickle

# https://pythonprogramming.net/pickle-objects-sockets-tutorial-python-3/
HEADERSIZE = 10


class My_server:
    def __init__(self, ip):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind(ip)
        self.s.listen(5)
        self.ip = ip

    def start_server(self):
        self.lister_thread = threading.Thread(target=self.listen_to_clients)
        self.lister_thread.start()

    def listen_to_clients(self):
        while True:
            # now our endpoint knows about the OTHER endpoint.
            client_socket, address = self.s.accept()
            print(f"Connection from {address} has been established.")
            self.start_connection()
            '''
            d = self.recieve_data(client_socket)
            print(d)

            d = {1: "hi", 2: "there1"}
            self.send_data(client_socket, d)

            d = self.recieve_data(client_socket)
            print(d)
            d = {1: "hi", 2: "there3"}
            self.send_data(client_socket, d)

            client_socket.close()
            '''



    def shutdown(self):
        self.s.shutdown(socket.SHUT_WR)
        print(self.lister_thread.is_alive())
        print('server shut down')
        # todo close socket properly, thread is still working

    def send_data(self, s, d):
        msg = pickle.dumps(d)
        msg = bytes(f"{len(msg):<{HEADERSIZE}}", 'utf-8') + msg
        # print(msg)
        s.send(msg)

    def recieve_data(self, s):
        full_msg = b''
        new_msg = True
        while True:
            msg = s.recv(1024)
            if new_msg:
                # print("new msg len:", msg[:HEADERSIZE])
                msglen = int(msg[:HEADERSIZE])
                new_msg = False

            # print(f"full message length: {msglen}")

            full_msg += msg

            # print(len(full_msg))

            if len(full_msg) - HEADERSIZE == msglen:
                # print("full msg recvd")
                # print(full_msg[HEADERSIZE:])
                # print(pickle.loads(full_msg[HEADERSIZE:]))
                return pickle.loads(full_msg[HEADERSIZE:])
                new_msg = True
                full_msg = b""
