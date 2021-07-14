import random

from certificate_authority.ca import find_client_public_key_from_my_datasource
from util.DNS import DNS
from util.Items_to_buy import items_to_buy
from util.keyUtil import *
from util.my_client import My_client


class Buyer:
    def __init__(self):
        # self.private_key, self.public_key = load_key_from_file('buyer/')
        # _, self.ca_public_key = load_key_from_file('certificate_authority/')
        self.private_key, self.public_key = load_key_from_file('./')
        _, self.ca_public_key = load_key_from_file('../certificate_authority/')
        self.ip = DNS.buyer.value

        self.get_ca()

    def get_ca(self):
        csr = make_csr(u"My Buy", u"192.168.0.1:65432", self.private_key)

        ca_client = My_client(DNS.ca.value)

        d = {'ip': self.ip, 'csr': csr.public_bytes(serialization.Encoding.PEM)}
        ca_client.send_data(ca_client.client_socket, d)

        d = ca_client.recieve_data(ca_client.client_socket)
        print(f'certificate received from CA: {d["cert"]}')
        self.cert = load_cert(d["cert"])
        ca_client.close_client()

    def buy(self, item, price):
        # 1. delegation
        blockChain_client = My_client(DNS.blockchain.value)
        time_stamp, naunce = datetime.datetime.utcnow(), random.randint(0, 1000000)
        d = {'ip': self.ip, 'message': 'delegation', 'naunce': naunce}
        blockChain_client.send_data(blockChain_client.client_socket, d)
        # 22
        d = blockChain_client.recieve_data(blockChain_client.client_socket)
        peer_cert = load_cert(d['cert'])
        peer_naunce = d['naunce']
        print(d)
        verify_crt(self.ca_public_key, peer_cert)
        peer_public_key = peer_cert.public_key()
        # 3
        d = {'ip': self.ip, 'cert': self.cert.public_bytes(serialization.Encoding.PEM), 'naunce': naunce,
             'enc_naunce': encrypt_with_public_key(peer_public_key, {'n': peer_naunce, 't': time_stamp})}
        blockChain_client.send_data(blockChain_client.client_socket, d)
        # 4
        d = blockChain_client.recieve_data(blockChain_client.client_socket)
        d = decrypt_with_private_key(self.private_key, d['enc_naunce'])
        print(d)
        if d['n'] != naunce:
            blockChain_client.close_client()
            print('reply attack')
        if datetime.datetime.utcnow() - d['t'] > datetime.timedelta(days=1):
            blockChain_client.close_client()
            print('reply attack')
        session_key = d['session_key']

        skm, pkm = generate_key()
        policy = {'range': price, 'count': 1, 'time': datetime.datetime.utcnow() + datetime.timedelta(days=1),
                  'receiver': DNS.merchant.value}
        deligation = {'pkd': find_client_public_key_from_my_datasource(DNS.merchant.value).public_bytes(encoding=serialization.Encoding.PEM,  format=serialization.PublicFormat.SubjectPublicKeyInfo ), 'pkm': pkm.public_bytes(encoding=serialization.Encoding.PEM,  format=serialization.PublicFormat.SubjectPublicKeyInfo ),
                      'policy': policy, 'sig': sign_with_private_key(skm, {
                'pkd': find_client_public_key_from_my_datasource(DNS.merchant.value).public_bytes(encoding=serialization.Encoding.PEM,  format=serialization.PublicFormat.SubjectPublicKeyInfo ), 'policy': policy})}
        d = {'ip':self.ip, 'message': encrypt_message(deligation, session_key)}
        blockChain_client.send_data(blockChain_client.client_socket, d)
        blockChain_client.close_client()


if __name__ == '__main__':
    my_buyer = Buyer()
    print('which item do you want to buy?')
    print(items_to_buy)
    item = int(input())
    my_buyer.buy(item, items_to_buy['item' + str(item)])
