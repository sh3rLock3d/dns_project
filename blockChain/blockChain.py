import random
import threading

from util.DNS import DNS
from util.keyUtil import *
from util.my_client import My_client
from util.my_server import My_server


class BlockChain():
    def __init__(self):
        self.private_key, self.public_key = load_key_from_file('./')
        _, self.ca_public_key = load_key_from_file('../certificate_authority/')
        self.ip = DNS.blockchain.value
        self.get_ca()

        self.server = My_server(self.ip)
        self.listen_thread = threading.Thread(target=self.listen_to_clients)
        self.listen_thread.start()

    def get_ca(self):
        csr = make_csr(u"My Buy", u"192.168.0.1:65432", self.private_key)

        ca_client = My_client(DNS.ca.value)

        d = {'ip': self.ip, 'csr': csr.public_bytes(serialization.Encoding.PEM)}
        ca_client.send_data(ca_client.client_socket, d)

        d = ca_client.recieve_data(ca_client.client_socket)
        print(f'certificate received from CA: {d["cert"]}')
        self.cert = load_cert(d["cert"])
        ca_client.close_client()

    def listen_to_clients(self):
        while True:
            client_socket, address = self.server.s.accept()
            print(f"Connection from {address} has been established.")
            time_stamp, naunce = datetime.datetime.utcnow(), random.randint(0, 1000000)
            # 1
            d = self.server.recieve_data(client_socket)
            contex = d['message']
            peer_naunce = d['naunce']
            peer_ip = d['ip']
            print(d)
            # 2
            d = {'ip': self.ip, 'cert': self.cert.public_bytes(serialization.Encoding.PEM), 'naunce': naunce}
            self.server.send_data(client_socket, d)
            # 3
            d = self.server.recieve_data(client_socket)
            print(d)
            if decrypt_with_private_key(self.private_key, d['enc_naunce'])['n'] != naunce:
                client_socket.close()
                print('reply attack')
            if datetime.datetime.utcnow() - decrypt_with_private_key(self.private_key, d['enc_naunce'])[
                't'] > datetime.timedelta(days=1):
                client_socket.close()
                print('reply attack')
            peer_cert = load_cert(d['cert'])
            verify_crt(self.ca_public_key, peer_cert)
            peer_public_key = peer_cert.public_key()
            session_key = generate_Fernet_key()
            # 4
            d = {'ip': self.ip, 'enc_naunce': encrypt_with_public_key(peer_public_key,
                                                                      {'n': peer_naunce, 't': time_stamp,
                                                                       'session_key': session_key})}
            self.server.send_data(client_socket, d)
            print(f"secure Connection from {address} has been established with session: {session_key}.")
            if contex == 'delegation':
                pass
            else:
                pass

            client_socket.close()


if __name__ == '__main__':
    my_blockChain = BlockChain()
