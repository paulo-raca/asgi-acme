import asyncio
from asyncio.sslproto import SSLProtocol
from dataclasses import dataclass
from functools import partial
from ssl import SSLContext, SSLObject
import sys
import threading
from typing import Optional
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.requests import Request

from hypercorn.config import Config
from hypercorn.asyncio import serve
from acme_middleware import AcmeMiddleware
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
        loop = asyncio.get_event_loop()
        context = super().create_ssl_context()
        context.sni_callback = partial(self.sni_callback, loop)
        return context
        
    def sni_callback(
        self, loop: asyncio.AbstractEventLoop, sslobject: SSLObject, hostname: str, sslcontext: SSLContext
    ) -> None:
        """
        Set sslobject.context as appropriate for hostname.
        """
        print("sni_callback", loop, hostname, sslobject, sslcontext)
        print("thread", threading.get_native_id())
        print("selected_alpn_protocol()", sslobject.selected_alpn_protocol())

        import traceback
        traceback.print_stack()
        #if hostname:
            #loop.create_task(acme.get_certificate(hostname))
            #sslobject.context = self.certificate_for_hostname(
            #    self.create_ssl_context(), hostname, sslobject._probably_acme
            #)
            #pass
        # TODO return error code on exception


config = MyConfig()
config.insecure_bind = ["[::]:80"]
config.bind = ["[::]:443"]

asyncio.run(serve(LogMiddleware(acme), config))
