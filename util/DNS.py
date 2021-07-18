from enum import Enum


class DNS(Enum):
    buyer = ('127.0.0.1', 65432)
    merchant = ('127.0.0.1', 65433)
    bank = ('127.0.0.1', 65434)
    blockchain = ('127.0.0.1', 65435)
    ca = ('127.0.0.1', 65440)