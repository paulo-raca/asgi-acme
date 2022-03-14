import asyncio
from asyncio.sslproto import SSLProtocol
from dataclasses import dataclass
from functools import partial
from multiprocessing import context
from os import system
from ssl import SSLContext, SSLObject
import sys
import tempfile
import threading
from time import sleep
from typing import Optional
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.requests import Request
from asgi_acme.certificate import Certificate

from hypercorn.config import Config
from hypercorn.asyncio import serve
from .acme_middleware import AcmeMiddleware
from cryptography.hazmat.primitives import serialization
from cryptography import x509

async def homepage(request):
    return JSONResponse({'hello': 'world'})

async def gen_cert(request: Request):
    cert = await acme.get_certificate(request.headers["host"])
    return JSONResponse({'cert': cert})

app = Starlette(debug=True, routes=[
    Route('/', homepage),
    Route('/cert', gen_cert),
])
acme = AcmeMiddleware(app)


@dataclass
class LogMiddleware:
    app: 'ASGIApp'

    async def __call__(self, scope: 'Scope', receive: 'Receive', send: 'Send') -> None:
        headers = dict(scope["headers"])
        host = headers.get("host", "localhost")
        url = f'{scope["scheme"]}://{host}{scope["raw_path"].decode("utf-8")}'
        print(f'{scope["method"]} {url}')
        await self.app(scope, receive, send)


def show_data_received(self: SSLProtocol, data: bytes) -> bytes:
    print("data_received", data)

#SSLProtocol.data_received = show_data_received

class MyConfig(Config):
    alpn_protocols = Config.alpn_protocols + ["acme-tls/1"]

    @property 
    def ssl_enabled(self) -> bool:
        return True

    def create_ssl_context(self) -> Optional[SSLContext]:
        context = super().create_ssl_context()
        context.sni_callback = self.sni_callback
        return context
        
    def sni_callback(
        self, sslobject: SSLObject, hostname: str, sslcontext: SSLContext
    ) -> None:
        """
        Set sslobject.context as appropriate for hostname.
        """
        #print("sni_callback", hostname, sslobject, sslcontext)
        #print("selected_alpn_protocol()", sslobject.selected_alpn_protocol())
        if hostname:
            cert: Certificate = acme.get_certificate(hostname)
            chain = cert.signed_cert or cert.alpn_cert or cert.self_signed_cert
            if isinstance(chain, x509.Certificate):
                chain = chain.public_bytes(serialization.Encoding.PEM)

            with (
                tempfile.NamedTemporaryFile() as keyfile,
                tempfile.NamedTemporaryFile() as certfile,
            ):
                certfile.write(chain)
                certfile.flush()
                keyfile.write(cert.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
                keyfile.flush()
                sslcontext.load_cert_chain(certfile.name, keyfile.name)


config = MyConfig()
config.insecure_bind = ["[::]:80"]
config.bind = ["[::]:443"]

asyncio.run(serve(LogMiddleware(acme), config))
