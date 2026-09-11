import base64
import json
import re
import logging
import time
import urllib.parse
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from openg2p_fastapi_common.service import BaseService

from ..config import Settings

_config = Settings.get_config()
_logger = logging.getLogger(_config.logging_default_logger_name)


# Velocity leaves an undefined reference in the output verbatim, so this is
# what an unrendered template variable looks like in a signed credential.
_PLACEHOLDER = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_.()\[\]]*\}")


class CertifyIssuanceError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class CertifyIssuanceService(BaseService):
    """Pushes claims into Inji Certify via the pre-authorized-code flow.

    Phase-1 has no wallet: the agent portal acts as the OpenID4VCI client.
    It seeds the offer with the registrant's claims (consumed by Certify's
    stock ``PreAuthDataProviderPlugin``), redeems the pre-authorized code for
    an access token, and requests the signed credential with a fresh
    proof-of-possession JWT.
    """

    PRE_AUTH_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

    async def issue(
        self, claims: dict[str, Any], config_id: str, credential_types: list[str]
    ) -> Any:
        base = _config.certify_base_url.rstrip("/")
        async with httpx.AsyncClient(timeout=_config.certify_http_timeout) as client:
            offer_id = await self._create_offer(client, base, claims, config_id)
            pre_auth_code = await self._read_offer(client, base, offer_id)
            access_token, c_nonce = await self._exchange_token(
                client, base, pre_auth_code
            )
            return await self._request_credential(
                client, base, access_token, c_nonce, credential_types
            )

    async def _create_offer(
        self, client: httpx.AsyncClient, base: str, claims: dict[str, Any], config_id: str
    ) -> str:
       
        _logger.info(
                "Sending claims to Inji Certify. claim_keys=%s",
                list(claims.keys()),
            )
        resp = await client.post(
            f"{base}/pre-authorized-data",
            json={
                "credential_configuration_id": config_id,
                "claims": claims,
                "expires_in": _config.certify_offer_expires_in,
                "tx_code": _config.certify_tx_code,
            },
        )
        self._raise_for_status(resp, "PRE_AUTHORIZED_DATA_FAILED")
        offer_uri = resp.json()["credential_offer_uri"]
        return urllib.parse.unquote(offer_uri).rstrip("/").split("/")[-1]

    async def _read_offer(
        self, client: httpx.AsyncClient, base: str, offer_id: str
    ) -> str:
        resp = await client.get(f"{base}/credential-offer-data/{offer_id}")
        self._raise_for_status(resp, "CREDENTIAL_OFFER_FETCH_FAILED")
        grants = resp.json()["grants"]
        return grants[self.PRE_AUTH_GRANT]["pre-authorized_code"]

    async def _exchange_token(
        self, client: httpx.AsyncClient, base: str, pre_auth_code: str
    ) -> tuple[str, str]:
        resp = await client.post(
            f"{base}/oauth/token",
            data={
                "grant_type": self.PRE_AUTH_GRANT,
                "pre-authorized_code": pre_auth_code,
                "tx_code": _config.certify_tx_code,
            },
        )
        self._raise_for_status(resp, "TOKEN_EXCHANGE_FAILED")
        body = resp.json()
        return body["access_token"], body.get("c_nonce", "")

    async def _request_credential(
        self,
        client: httpx.AsyncClient,
        base: str,
        access_token: str,
        c_nonce: str,
        credential_types: list[str],
    ) -> Any:
        proof = self._make_proof_jwt(c_nonce)
        resp = await client.post(
            f"{base}/issuance/credential",
            headers={"Authorization": f"Bearer {access_token}"},
            json={
                "format": _config.certify_credential_format,
                "credential_definition": {
                    "@context": _config.certify_credential_context,
                    "type": credential_types,
                },
                "proof": {"proof_type": "jwt", "jwt": proof},
            },
        )
        self._raise_for_status(resp, "CREDENTIAL_ISSUANCE_FAILED")
        body = resp.json()
        # Return the CREDENTIAL, not the OpenID4VCI envelope that wraps it.
        # Certify answers {"credential": {...}, "format": ...}; handing that
        # envelope on makes every consumer one level too deep. The visible
        # symptom was the QR: the compact claim-169 payload sits at
        # credential.claim169.qrCode, the configured qr_claim_path could not
        # find it, and the renderer silently fell back to embedding the whole
        # response -- so the QR carried the envelope instead of the signed
        # compact credential, and was far larger for it.
        if isinstance(body, dict) and isinstance(body.get("credential"), dict):
            body = body["credential"]
        self._reject_unresolved_placeholders(body)
        return body

    @staticmethod
    def _reject_unresolved_placeholders(credential: Any) -> None:
        """Refuse a credential still carrying Velocity placeholders.

        Certify renders the VC from a Velocity template. A name the context does
        not define is NOT an error there -- Velocity emits it verbatim -- so a
        typo in vcTemplateJson produces a credential containing the literal text
        "${fullName}", and Certify SIGNS it. It then passes every check we make,
        prints onto the card, and is only noticed by whoever reads the paper.

        This turns that into a failed issuance. The beneficiary is still inside
        their authentication window and the agent can retry once the template is
        fixed, which is a far better outcome than a signed, wrong credential.
        """
        leftovers = sorted(set(_PLACEHOLDER.findall(json.dumps(credential))))
        if leftovers:
            raise CertifyIssuanceError(
                "CREDENTIAL_TEMPLATE_UNRESOLVED",
                "Certify returned a credential with unresolved template "
                f"placeholders: {', '.join(leftovers)}. Fix the vcTemplateJson "
                "for this credential type -- these names are not supplied by the "
                "claim set, so the credential would be signed with literal "
                "placeholder text.",
            )

    def _make_proof_jwt(self, nonce: str) -> str:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = priv.public_key()
        pn = pub.public_numbers()
        n = pn.n.to_bytes((pn.n.bit_length() + 7) // 8, "big")
        e = pn.e.to_bytes((pn.e.bit_length() + 7) // 8, "big")
        jwk = {"kty": "RSA", "n": _b64url(n), "e": _b64url(e), "alg": "RS256", "use": "sig"}
        header = {"alg": "RS256", "typ": "openid4vci-proof+jwt", "jwk": jwk}
        payload = {
            "aud": _config.certify_audience,
            "nonce": nonce,
            "iss": "",
            "iat": int(time.time()),
        }
        signing_input = (
            _b64url(json.dumps(header).encode())
            + "."
            + _b64url(json.dumps(payload).encode())
        ).encode()
        sig = priv.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return signing_input.decode() + "." + _b64url(sig)

    def _raise_for_status(self, resp: httpx.Response, code: str) -> None:
        if resp.status_code >= 400:
            _logger.error("Certify call failed (%s): %s", resp.status_code, resp.text)
            raise CertifyIssuanceError(
                code, f"Certify returned {resp.status_code}: {resp.text}"
            )
