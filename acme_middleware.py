import asyncio
import base64
from io import UnsupportedOperation
import json
from contextlib import asynccontextmanager
import threading
from typing import Any, Awaitable, Callable, Optional
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
from urllib3.util.retry import Retry
from starlette.responses import PlainTextResponse
from OpenSSL import crypto, SSL

import aiohttp
import time

#LETSENCRYPT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"

Challenge = Any
ChallengeSolver = Callable[[str, Challenge], Awaitable[bool]]

class AcmeClient:
    @staticmethod
    @asynccontextmanager
    async def create(
        challenge_solver: ChallengeSolver,
        account_key: JWK = JWK.generate(kty='RSA', size=4096),
        directory_url: str = LETSENCRYPT_DIRECTORY
    ):
        headers = {
            "User-Agent": "AcmeClient"
        }
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(directory_url) as response:
                assert response.status == 200, "Failed to read directory"
                acme_client = AcmeClient(
                    challenge_solver,
                    account_key=account_key,
                    directory=await response.json(),
                    session=session,
                )
                await acme_client.get_account_location()
                yield acme_client


    def __init__(
        self,
        challenge_solver: ChallengeSolver, 
        account_key: JWK,
        directory: Any, 
        session: aiohttp.ClientSession, 
    ):
        self.challenge_solver = challenge_solver
        self.account_key = account_key
        self.directory = directory
        self.session = session
        self._account_location = None
        self._replay_nonce = None

    async def get_nonce(self) -> str:
        if self._replay_nonce is not None:
            ret = self._replay_nonce
            self._replay_nonce = None
            return ret
        async with self.session.head(self.directory["newNonce"]) as response:
            assert response.status == 200, "Failed to get nonce"
            return response.headers["replay-nonce"]

    async def signed_request(self, url: str, payload: Any, name: str, retries: int = 10) -> Any:
        retry = 0
        while True:
            retry += 1
            if payload is None:
                payload_data = b""
            else:
                payload_data = json.dumps(payload).encode("utf-8")
            protected_data = {
                "url": url,
                "alg": "RS256",
                "nonce": await self.get_nonce()
            }
            if self._account_location is not None:
                protected_data["kid"] = self._account_location
            else:
                protected_data["jwk"] = self.account_key.export_public(as_dict=True)
                
            jwstoken = JWS(payload_data)
            jwstoken.add_signature(self.account_key, None, protected_data)

            async with self.session.post(
                url, 
                data=jwstoken.serialize(), 
                headers={'content-type': 'application/jose+json'}
            ) as response:
                self._replay_nonce = response.headers.get("Replay-Nonce", self._replay_nonce)


                if response.status not in [200, 201, 204]:
                    if response.headers.get('content-type') == 'application/problem+json':
                        problem = await response.json()
                        if retry <= retries:
                            if problem["type"] == "urn:ietf:params:acme:error:badNonce":
                                continue  # retry
                            elif problem["type"] == "urn:ietf:params:acme:error:rateLimited":
                                wait_seconds = Retry().parse_retry_after(response.headers.get("Retry-After", "10"))
                                #print(f"rateLimited - Waiting {wait_seconds} seconds")
                                await asyncio.sleep(wait_seconds)
                                continue  # retry
                        raise IOError(f"Failed to {name}: {problem['detail']}")
                    else:
                        raise IOError(f"Failed to {name}: status={response.status}")

                return response.headers, await response.json()

    async def get_account_location(self):
        if self._account_location is None:
            payload = {
                "termsOfServiceAgreed": True,
            }
            response_headers, _ = await self.signed_request(self.directory["newAccount"], payload, "create account")
            self._account_location = response_headers["Location"]
        return self._account_location

    async def new_order(self, domains: list[str], timeout: float = 30):
        payload = {
            "identifiers": [
                {
                    "type": "dns", 
                    "value": d,
                }
                for d in domains
            ],
        }
        order_headers, order_body = await self.signed_request(self.directory["newOrder"], payload, "create order")
        order_url = order_headers["Location"]

        if order_body["status"] != "valid":
            # Perform challenges to each domain
            await asyncio.gather(*[
                self._do_authorization(authorization_url, timeout)
                for authorization_url in order_body["authorizations"]
            ])

            # Wait until 
            identifiers = ", ".join(domains)
            await self.wait_pending(order_url, f"order for {identifiers}", timeout)

    async def _do_authorization(self, authorization_url: str, timeout: Optional[float] = None):
        _, authorization_body = await self.signed_request(authorization_url, None, "access authorization")
        if authorization_body['status'] == "valid":
            return True
        
        identifier = authorization_body["identifier"]["value"]
        challenge_done = await asyncio.gather(*[
            self._do_challenge(identifier, challenge)
            for challenge in authorization_body["challenges"]
        ])
        if not any([x is True for x in challenge_done]):
            types = ', '.join(
                challenge['type'] 
                for challenge in authorization_body['challenges']
            )
            raise NotImplementedError(
                f"Couldn't perform challenge for {identifier}: {types}")

        if timeout is not None:
            await self.wait_pending(authorization_url, f"authorization to {identifier}", timeout)

        print(f"authorization complete for {identifier}")

    async def _do_challenge(self, domain: str, challenge: Challenge) -> bool:
        print("_do_challenge", json.dumps(challenge, indent=4))
        if challenge["status"] == "valid":
            return True

        if await self.challenge_solver(domain, challenge):
            # Challenge complete, notify ACME server
            headers, response = await self.signed_request(challenge["url"], {}, "mark challenge complete")
            print(f"Challenge complete for {domain}: {challenge['type']}")
            print(json.dumps(response, indent=4))
            return True
        return False

    async def wait_pending(self, url: str, name: str, wait_for: float = 10):
        start_time = time.monotonic()
        while True:
            _, authorization_body = await self.signed_request(url, None, "poll authorization status")
            status = authorization_body['status']
            if status in ["valid", "ready"]:
                return status  # Done
            elif status in ["pending", "processing"]:
                elapsed = time.monotonic() - start_time
                if elapsed > wait_for:
                    raise TimeoutError(f"timeout waiting for {name} after {wait_for}s: status={status}")
                await asyncio.sleep(1)
                continue
            else:
                raise ValueError(f"Unexpected state for {name}: {status}")


class AcmeMiddleware:
    PATH_PREFIX = "/.well-known/acme-challenge/"

    def __init__(
        self,
        app: 'ASGIApp',
        directory_url: str = LETSENCRYPT_DIRECTORY,
        #account_key: 
    ):
        self.app = app
        self.directory_url = directory_url
        self.account_key = JWK.generate(kty='RSA', size=2048)
        #self.account_key = JWK(**{"d":"g310Zved54mYXhpNZXxlPxShjgwXA7Mr4e827PRAA6R73I_nENmLMtFGvS99E4dPTS1wHIEb8Jz_cxAci9F-83skdSnyQhk7MQCtmfJUSgTn0IqMCX1aKcDEhEB_uNO2XCPqW5LQbzhnX7eMkkzrDYMWp5Y1XPe1AA-6yt-AeielLUtGt8e2nFfeHPg1QemBfgx1B6o5EoQrlWD2ZwV7bm_p96u1JJ7KoQJq0us14Ddjz8lw9VbzQwWgB9q92SP2ygMguLUE7Y453uMx5nRVoQYUSAcIgOBP1tk0moGLAjH5h58X-DtLSNRUSGO1Xd9ro2vtqyehTJN_eKDeNqGlAQ","dp":"mDF1bzSe9Lw0ax_I_JvpaKpe4ZaCI_HAhmnx23dI6E5-HcOWV9cn9LLibZFtgQ4GtPM8Nu5Sy4bnyXy6i1igA2859MpgaUlbw3rbzSKNpubGGpJt_vu600qyl2AtlTE4AVQDRCeU4JzwA_0VKYzcfGaLJySXW3CLyctB63saniE","dq":"uT282YJQBR3F0JY0s-6Wti82nunPidSHQR0ePI8G5i_cNfFsnLRokp72MaadCtv5oSMul5Aeo4CiVY4ZCPq9EXVLsASJUnu-WqL1jBN8U4PiWwu6WADyjpgSYAw54LmGPneyogbYzD6EYbo40jdoJdqGuHz1bYBZ7EjJhKJeVYE","e":"AQAB","kty":"RSA","n":"uPvRRSA5Upj6f10MuHSEGtl5ySeWtVMxB6k48vR-GzRiX0bZaRGOzyTEToePbaDkMNi4kN0XMbt-3CxsD09q0XBGV4gnlq9GcijHV1CfkHkrz60RUOS2udAxLYX-FXvPkwdy68oDj6h2b6BRHwpSee5iBLhAr78fN7tvF2f-3bjSLBQWt06dXEuQSpErgfg53CvnmEDYkNpuC_xTLqmCBR18IHdWBjz2bQaDtXaAdVQ-vttjScc5fUjUPocXcAwTihm9fpheUXwFdjfUCa191gB7Zv5mCFfRpmtBlYSXRmprbAg5ihWW2q5HwZHe7EjFkpircIBzR5xYxEklr7zJHQ","p":"6E5OtQeSutr-Fon4QFPLjvnkT3-d5eJboW2ErtLCg4CWOq4HszCanXiT3onSCHa4nMxA7l3VguVbJ6oqgArxbae90WBVyNKrH_M2YG_3R59YG57vpc_JhaM2iD6cSyqUEpQuIDa3f7NmOWmETwBesJlx1-5wF7Stx_K20oZzrV0","q":"y9njijbW-ujX0WuVMnRDY3PZ7GIJSJHQWA31iSg9yPSEC03F5E3YSzTm_kaCSfU0Nz_VVclL8BMlNaym_SLaeVE0srhqos1J2heBccn1oJ-FbuM2vMrWSvZH2zKjLgBSf8NpUKPOhw9HrR3aGvHZuwKSsvVxNd6N5D4Y1b58DsE","qi":"qhH2HIA_b7klM__7QcT3xIemkZzIkrhhm6ER2hM9r6htefX4IntJDZbxdPSufaOfCC_dvgOMQC5jaGo62ZHSqYg9bVNbhpsnKDwkLnoEfECuOsf6hCF04jmqHDmGlWHbe1JOqSI0I5MmA9WCMTVD6Bd14MeSriL7QjBbYQBLCBk"})
        self.challenges = {}
        #self.loop = asyncio.get_running_loop()

    async def perform_challenge(self, domain: str, challenge: Challenge) -> bool:
        if challenge["type"] in ["xhttp-01", "tls-alpn-01"]:
            self.challenges[challenge["token"]] = f"{challenge['token']}.{self.account_key.thumbprint()}"
            return True
        
        return False

    async def get_certificate(self, *hosts: list[str]):
        async with AcmeClient.create(self.perform_challenge, self.account_key, self.directory_url) as acme_client:
            tls_key = crypto.PKey()
            tls_key.generate_key(crypto.TYPE_RSA, 1024)

            await acme_client.new_order(hosts)

    async def __call__(self, scope: 'Scope', receive: 'Receive', send: 'Send') -> None:       
        if scope["type"] == "http" and scope["method"] == "GET" and scope["path"].startswith(self.PATH_PREFIX):
            token = scope["path"][len(self.PATH_PREFIX):]
            if token in self.challenges:
                response = PlainTextResponse(self.challenges[token])
                print("ACME Token: ", token, "response=", response.body)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)

async def main():
    await AcmeMiddleware().get_certificate("inutilfutil.com")

if __name__ == "__main__":
    asyncio.run(main())
