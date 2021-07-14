import datetime
import pickle

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


def print_private_key(k):
    pem = k.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    print(pem.splitlines())


def print_public_key(k):
    pem = k.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(pem.splitlines())


def generate_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


PADDING = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def write_key_to_file(path):
    private_key, public_key = generate_key()
    with open(path + "private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(path + "public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))


def load_key_from_file(path):
    with open(path + "private.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    with open(path + "public.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
        )
    return private_key, public_key


def encrypt_dictionary_with_public_key(puk, d):
    message = pickle.dumps(d)
    print(puk)
    ciphertext = puk.encrypt(
        message,
        padding.PKCS1v15(),
    )
    return {'body': ciphertext}


def decrypt_dictionary_with_private_key(prk, encd):
    de = encd
    plaintext = prk.decrypt(
        encd['body'],
        padding.PKCS1v15(),
    )
    de['body'] = pickle.loads(plaintext)
    return de


def make_csr(company, common_name, se_private_key):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, company),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])).add_extension(
        x509.SubjectAlternativeName([

            x509.DNSName(common_name),
            x509.DNSName(u"www" + common_name),
            x509.DNSName(u"subdomain." + u"mysite.com"),
        ]),
        critical=False,
        # Sign the CSR with our private key.
    ).sign(se_private_key, hashes.SHA256())
    return csr


def load_csr(data):
    return x509.load_pem_x509_csr(data)


def load_cert(data):
    return x509.load_pem_x509_certificate(data)


def sign_certificate(se_public_key, ca_private_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        se_public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
        # Sign our certificate with our private key
    ).sign(ca_private_key, hashes.SHA256())
    return cert


def verify_csr(client_public_key, csr_to_check):
    client_public_key.verify(
        csr_to_check.signature,
        csr_to_check.tbs_certrequest_bytes,
        # Depends on the algorithm used to create the certificate
        padding.PKCS1v15(),
        csr_to_check.signature_hash_algorithm,
    )
