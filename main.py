from buyer.buyer import Buyer
from merchant.merchant import Merchant
from util.my_client import My_client
from util.my_server import My_server

'''
ip = ('127.0.0.1', 1243)
my_server = My_server(ip)
my_client = My_client(ip)

my_client.send_message()

print("sdds")

my_client = My_client(ip)

#my_client.send_message()

my_server.shutdown()
'''

my_merchant = Merchant()
my_buyer = Buyer()
