import threading

from util.DNS import DNS
from util.keyUtil import *
from util.my_server import My_server


def find_client_public_key_from_my_datasource(ip):
    path = None
    if DNS(ip)==DNS.merchant:
        path = '../merchant/'
    elif DNS(ip)==DNS.buyer:
        path = '../buyer/'
    elif DNS(ip)==DNS.bank:
        path = '../bank/'
    elif DNS(ip)==DNS.blockchain:
        path = '../blockChain/'
    if path is None: raise Exception("invalid ip")
    _, client_public_key = load_key_from_file(path)
    return client_public_key


class CA:
    def __init__(self):
        #self.private_key, self.public_key = load_key_from_file('certificate_authority/')
        self.private_key, self.public_key = load_key_from_file('./')
        self.ip = DNS.ca.value
        self.server = My_server(self.ip)
        self.listen_thread = threading.Thread(target=self.listen_to_clients)
        self.listen_thread.start()

    def listen_to_clients(self):
        while True:
            # now our endpoint knows about the OTHER endpoint.
            client_socket, address = self.server.s.accept()
            print(f"Connection from {address} has been established.")

            d = self.server.recieve_data(client_socket)

            print(f'certificate request from {d["ip"]} with csr:')
            print("\t",d['csr'])

            client_csr = load_csr(d['csr'])
            client_pk = find_client_public_key_from_my_datasource(d["ip"])
            verify_csr(client_pk, client_csr)
            cert = sign_certificate(client_pk, self.private_key)

            d = {'cert': cert.public_bytes(serialization.Encoding.PEM)}
            self.server.send_data(client_socket, d)

            client_socket.close()


if __name__ == '__main__':
    my_ca = CA()