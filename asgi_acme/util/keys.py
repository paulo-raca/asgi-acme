from cryptography.hazmat.primitives.asymmetric import rsa
from jwcrypto.jwk import JWK

def new_account_key() -> JWK:
    return JWK.generate(kty='RSA', size=2048)

def new_tls_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )