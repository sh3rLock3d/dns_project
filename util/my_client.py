import socket
import pickle

HEADERSIZE = 10


class My_client:
    def __init__(self, ip):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(ip)
        self.ip = ip

    def send_message(self):
        d = {1: "hi", 2: "there"}
        self.send_data(self.client_socket, d)

        d = self.recieve_data(self.client_socket)
        print(d)

        d = {1: "hi", 2: "there2"}
        self.send_data(self.client_socket, d)

        d = self.recieve_data(self.client_socket)
        print(d)

    def close_client(self):
        self.client_socket.close()
        print("client close")

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
