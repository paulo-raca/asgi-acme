import asyncio
import base64
from io import BytesIO
import json
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from contextlib import asynccontextmanager
from typing import Any, Awaitable, Callable, Optional

from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
from urllib3.util.retry import Retry
from .util.keys import new_account_key

import aiohttp
import time

LETSENCRYPT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"

AcmeChallenge = Any
AcmeChallengeSolver = Callable[[str, JWK, AcmeChallenge], Awaitable[bool]]

class AcmeClient:
    @staticmethod
    @asynccontextmanager
    async def create(
        challenge_solver: AcmeChallengeSolver,
        account_key: JWK = new_account_key(),
        directory_url: str = LETSENCRYPT_DIRECTORY
    ):
        headers = {
            "User-Agent": "ASGI-Acme"
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
        challenge_solver: AcmeChallengeSolver, 
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

    async def signed_request(self, url: str, payload: Any, name: str, retries: int = 10, blob: bool = False) -> Any:
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

                return response.headers, await response.read() if blob else await response.json()

    async def get_account_location(self):
        if self._account_location is None:
            payload = {
                "termsOfServiceAgreed": True,
            }
            response_headers, _ = await self.signed_request(self.directory["newAccount"], payload, "create account")
            self._account_location = response_headers["Location"]
        return self._account_location

    async def new_order(self, csr: x509.CertificateSigningRequest, timeout: float = 30):
        # Retrieve domain name from Subject Common Name
        domains = [
            attribute.value
            for attribute in csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        ]
        # Retrieve domain names from Subject Alternative Names
        try:
            domains += csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass  # No SubjectAltName extension
        print("Alt names:", domains)
        payload = {
            "identifiers": [
                {
                    "type": "dns", 
                    "value": domain,
                }
                for domain in domains
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
            order_headers, order_body = await self.wait_pending(order_url, f"order for {identifiers}", timeout)

        print("Order ready", order_body)
        order_headers, order_body = await self.signed_request(
            order_body["finalize"], 
            {"csr": base64.urlsafe_b64encode(csr.public_bytes(serialization.Encoding.DER)).decode()}, 
            "Finalize Signing Request"
        )
        print("Waiting for certificate", order_body)
        order_headers, order_body = await self.wait_pending(order_url, f"issued certificate", timeout)

        print("Fetching certificate", order_body)
        cert_headers, cert_body = await self.signed_request(order_body["certificate"], None, "fetch certificate", blob=True)
        print(cert_body.decode())
        return cert_body
        
        

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

    async def _do_challenge(self, domain: str, challenge: AcmeChallenge) -> bool:
        if challenge["status"] == "valid":
            return True

        if await self.challenge_solver(domain, self.account_key, challenge):
            # Challenge complete, notify ACME server

            headers, response = await self.signed_request(challenge["url"], {}, "mark challenge complete")
            print(f"Challenge complete for {domain}: {challenge['type']}")
            return True
        return False

    async def wait_pending(self, url: str, name: str, wait_for: float = 10):
        start_time = time.monotonic()
        while True:
            headers, body = await self.signed_request(url, None, name)
            status = body['status']
            if status in ["valid", "ready"]:
                return headers, body  # Done
            elif status in ["pending", "processing"]:
                elapsed = time.monotonic() - start_time
                if elapsed > wait_for:
                    raise TimeoutError(f"timeout waiting for {name} after {wait_for}s: status={status}")
                await asyncio.sleep(1)
                continue
            else:
                print(body)
                raise ValueError(f"Unexpected state for {name}: {status}")
