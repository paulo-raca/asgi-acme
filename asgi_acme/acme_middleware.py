import asyncio
import base64
from io import UnsupportedOperation
import json
from contextlib import asynccontextmanager
import threading
from typing import Any, Awaitable, Callable, Optional
from asgi_acme.certificate import Certificate
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
from urllib3.util.retry import Retry
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp
from .util.keys import new_account_key, new_tls_key
from .acme_client import LETSENCRYPT_STAGING_DIRECTORY, AcmeClient, AcmeChallenge, LETSENCRYPT_DIRECTORY

CHALLENGE_TYPE_HTTP_01 = "http-01"
CHALLENGE_TYPE_TLS_ALPN_01 = "tls-alpn-01"
HTTP_01_PATH_PREFIX = "/.well-known/acme-challenge/"

class AcmeMiddleware(ASGIApp):
    def __init__(
        self,
        app: ASGIApp,
        directory_url: str = LETSENCRYPT_DIRECTORY,
        account_key: JWK = new_account_key(),
    ):
        self.app = app
        self.directory_url = directory_url
        self.account_key = account_key
        self.http_01_challenges = {}
        self.certificates: list[Certificate] = []

    async def perform_challenge(self, domain: str, account_key: JWK, challenge: AcmeChallenge) -> bool:
        if challenge["type"] in [CHALLENGE_TYPE_HTTP_01, CHALLENGE_TYPE_TLS_ALPN_01]:
            token = challenge["token"]
            key_authorization = f"{token}.{account_key.thumbprint()}"
            if challenge["type"] == CHALLENGE_TYPE_HTTP_01:
                self.http_01_challenges[token] = key_authorization
            if challenge["type"] == CHALLENGE_TYPE_TLS_ALPN_01:
                self.get_certificate(domain, exact=True).set_alpn_challenge(key_authorization)

            return True
        
        return False

    def get_certificate(self, *hosts: list[str], exact=False) -> Certificate:
        for cert in self.certificates:
            if exact:
                if set(hosts) == set(cert.hosts):
                    return cert
            else:
                if all([ host in cert.hosts for host in hosts]):
                    return cert

        print(f"Creating certificate for {hosts}...")
        new_cert = Certificate(hosts)
        self.certificates.append(new_cert)

        async def sign_cert():
            async with AcmeClient.create(self.perform_challenge, self.account_key, self.directory_url) as acme_client:
                new_cert.signed_cert = await acme_client.new_order(new_cert.csr)
                print("Done!")

        asyncio.create_task(sign_cert())
        return new_cert

    async def __call__(self, scope: 'Scope', receive: 'Receive', send: 'Send') -> None:       
        if scope["type"] == "http" and scope["method"] == "GET" and scope["path"].startswith(HTTP_01_PATH_PREFIX):
            token = scope["path"][len(HTTP_01_PATH_PREFIX):]
            if token in self.http_01_challenges:
                response = PlainTextResponse(self.http_01_challenges[token])
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)

async def main():
    await AcmeMiddleware().get_certificate("inutilfutil.com")

if __name__ == "__main__":
    asyncio.run(main())
