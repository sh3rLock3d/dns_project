import socket


class Entity:
    def __init__(self, ip):
        self.ip = ip

    def listen_for_connection(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # AF_INET is the Internet address family for IPv4. SOCK_STREAM is the socket type for TCP
            s.bind(self.ip)
            s.listen()
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr)
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    conn.sendall(data)
