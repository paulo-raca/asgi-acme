import codecs
import hashlib
from typing import Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.types import PRIVATE_KEY_TYPES
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes

from datetime import datetime, timedelta
from .util import keys
from .util.hostnames import sorted_hostnames

ID_PE_ACME_IDENTIFIER = ObjectIdentifier("1.3.6.1.5.5.7.1.31")

DEFAULT_SUBJECT = x509.Name([
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ASGI ACME Middleware"),
])

class Certificate:
    def __init__(self, hosts: list[str], subject: x509.Name = DEFAULT_SUBJECT, key: PRIVATE_KEY_TYPES = keys.new_tls_key()):
        self.hosts = hosts
        self.subject = subject
        self.subjectAltName = x509.SubjectAlternativeName([
            x509.DNSName(host)
            for host in self.hosts
        ])
        self.key = key

        self.csr: x509.CertificateSigningRequest = x509.CertificateSigningRequestBuilder() \
            .subject_name(self.subject) \
            .add_extension(self.subjectAltName, critical=True) \
            .sign(self.key, hashes.SHA256())

        self.self_signed_cert: x509.Certificate = x509.CertificateBuilder() \
            .subject_name(self.subject) \
            .issuer_name(self.subject) \
            .add_extension(self.subjectAltName, critical=True) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(datetime.utcnow() - timedelta(minutes=15)) \
            .not_valid_after(datetime.utcnow() + timedelta(weeks=1)) \
            .public_key(self.key.public_key()) \
            .sign(self.key, hashes.SHA256())

        self.alpn_cert: x509.Certificate = None

        self.signed_cert: str = None

    def set_alpn_challenge(self, key_authorization: str):
        key_authorization_hash = hashlib.sha256(key_authorization.encode('utf-8')).digest()
        acme_extension = x509.UnrecognizedExtension(
            ID_PE_ACME_IDENTIFIER,
            bytes([0x4, len(key_authorization_hash)]) + key_authorization_hash)

        self.alpn_cert = x509.CertificateBuilder() \
            .subject_name(self.subject) \
            .issuer_name(self.subject) \
            .add_extension(self.subjectAltName, critical=True) \
            .add_extension(acme_extension, critical=True) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(datetime.utcnow() - timedelta(minutes=15)) \
            .not_valid_after(datetime.utcnow() + timedelta(weeks=1)) \
            .public_key(self.key.public_key()) \
            .sign(self.key, hashes.SHA256())

    def set_signed_cert(self, cert_data: bytes):
        self.signed_cert = x509.load_pem_x509_certificate(cert_data)
        assert self.signed_cert.public_key == self.key.public_key
