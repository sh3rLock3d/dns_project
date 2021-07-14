from util.DNS import DNS
from util.keyUtil import *
from util.my_client import My_client


class Merchant:
    def __init__(self):
        # self.private_key, self.public_key = load_key_from_file('merchant/')
        # _, self.ca_public_key = load_key_from_file('certificate_authority/')
        self.private_key, self.public_key = load_key_from_file('./')
        _, self.ca_public_key = load_key_from_file('../certificate_authority/')
        self.ip = DNS.merchant.value

        self.get_ca()

    def get_ca(self):
        csr = make_csr(u"My Company", u"mysite.com", self.private_key)

        ca_client = My_client(DNS.ca.value)

        d = {'ip': self.ip, 'csr': csr.public_bytes(serialization.Encoding.PEM)}
        ca_client.send_data(ca_client.client_socket, d)

        d = ca_client.recieve_data(ca_client.client_socket)
        print(f'certificate received from CA: {d["cert"]}')
        self.cert = load_cert(d["cert"])

        ca_client.close_client()


if __name__ == '__main__':
    my_merchant = Merchant()
