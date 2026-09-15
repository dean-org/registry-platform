import logging
import os
import time
from typing import Any, Dict, Optional

import httpx
from openg2p_fastapi_common.service import BaseService

from ..config import Settings

_config = Settings.get_config()
_logger = logging.getLogger(_config.logging_default_logger_name)


class CredIssuerError(Exception):
    """Raised when CredIssuer cannot issue or generate a credential PDF."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class CredIssuerService(BaseService):
    """Client for the CredIssuer credential issuance API.

    Flow:
        1. Submit credential data for issuance.
        2. Retrieve the issued credential using transaction_id.
        3. Create a PDF presentation.
        4. Download the generated PDF.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.base_url = (
            getattr(_config, "credential_api_base_url", None)
            or "https://api.credissuer.com/api"
        ).rstrip("/")

        self.token = getattr(_config, "credential_api_token", None)
        self.template_id = getattr(
            _config,
            "credential_api_template_id",
            None,
        )
        self.org_code = getattr(
            _config,
            "credential_api_org_code",
            None,
        )
        self.issuer_email = getattr(
            _config,
            "credential_api_issuer_email",
            None,
        )

        self.timeout = getattr(
            _config,
            "credential_api_http_timeout",
            60,
        )

        # Fallback photo used when a claim does not include one.
        # Resolution order (Kubernetes-friendly):
        #   1. CREDENTIAL_API_DEFAULT_PHOTO_PATH - path to a file mounted
        #      from a ConfigMap/Secret volume (recommended for large
        #      base64 photo blobs, since env vars have size limits).
        #   2. CREDENTIAL_API_DEFAULT_PHOTO - the photo value directly
        #      as an environment variable (e.g. injected from a Secret
        #      via `env`/`envFrom` in the pod spec).
        #   3. credential_api_default_photo on the app Settings object,
        #      if you'd rather wire it through your config layer.
        self.default_photo = self._load_default_photo()

        if not self.token:
            _logger.warning(
                "CredIssuer API token is not configured."
            )

        if not self.default_photo:
            _logger.info(
                "No default photo configured (CREDENTIAL_API_DEFAULT_PHOTO"
                " / CREDENTIAL_API_DEFAULT_PHOTO_PATH not set); "
                "credentials without a photo claim will omit the photo "
                "field."
            )

        _logger.info(
            "CredIssuerService initialized: base_url=%s, "
            "template_id=%s, org_code=%s, issuer_email=%s, "
            "timeout=%s, default_photo_configured=%s",
            self.base_url,
            self.template_id,
            self.org_code,
            self.issuer_email,
            self.timeout,
            bool(self.default_photo),
        )

    @staticmethod
    def _load_default_photo() -> Optional[str]:
        """Resolve the fallback photo from a mounted file, env var, or config."""

        photo_path = os.environ.get("CREDENTIAL_API_DEFAULT_PHOTO_PATH")

        if photo_path:
            try:
                with open(photo_path, "r", encoding="utf-8") as fh:
                    content = fh.read().strip()

                if content:
                    _logger.info(
                        "Loaded default photo from file: %s",
                        photo_path,
                    )
                    return content

                _logger.warning(
                    "CREDENTIAL_API_DEFAULT_PHOTO_PATH points to an "
                    "empty file: %s",
                    photo_path,
                )

            except OSError:
                _logger.exception(
                    "Could not read default photo file at "
                    "CREDENTIAL_API_DEFAULT_PHOTO_PATH=%s",
                    photo_path,
                )

        env_photo = os.environ.get("CREDENTIAL_API_DEFAULT_PHOTO")

        if env_photo:
            return env_photo

        return getattr(_config, "credential_api_default_photo", None)

    async def issue(self, claims: Dict[str, Any]) -> Dict[str, Any]:
        """Issue a credential and return the generated PDF information."""

        _logger.info(
            "Starting CredIssuer credential issuance: "
            "functionalRecordId=%s",
            claims.get("functionalRecordId"),
        )

        if not self.token:
            raise CredIssuerError(
                "G2P-VC-502",
                "CredIssuer API token is not configured.",
            )

        if not self.template_id:
            raise CredIssuerError(
                "G2P-VC-502",
                "CredIssuer credential template is not configured.",
            )

        credential_data = self._build_credential_data(claims)

        _logger.info(
            "CredIssuer credential data prepared: fields=%s",
            list(credential_data.keys()),
        )

        transaction = await self._issue_credential(credential_data)

        transaction_id = transaction.get("transaction_id")

        if not transaction_id:
            _logger.error(
                "CredIssuer issuance response did not contain transaction_id"
            )

            raise CredIssuerError(
                "G2P-VC-502",
                "CredIssuer did not return a transaction_id.",
            )

        _logger.info(
            "CredIssuer issuance accepted: transaction_id=%s",
            transaction_id,
        )

        issued = await self._get_issued_credential(transaction_id)

        results = issued.get("results") or []

        if not results:
            _logger.error(
                "CredIssuer returned no credentials: transaction_id=%s",
                transaction_id,
            )

            raise CredIssuerError(
                "G2P-VC-502",
                f"No credential was returned for transaction {transaction_id}.",
            )

        credential = results[0]

        status = str(
            credential.get("status", "")
        ).lower()

        _logger.info(
            "CredIssuer credential retrieved: transaction_id=%s, "
            "credential_id=%s, status=%s",
            transaction_id,
            credential.get("credential_id"),
            credential.get("status"),
        )

        if status in {"failed", "revoked"}:
            _logger.error(
                "CredIssuer credential issuance failed: transaction_id=%s, "
                "status=%s",
                transaction_id,
                credential.get("status"),
            )

            raise CredIssuerError(
                "G2P-VC-502",
                f"CredIssuer returned credential status: "
                f"{credential.get('status')}.",
            )

        credential_id = credential.get("credential_id")

        if not credential_id:
            _logger.error(
                "CredIssuer credential response did not contain "
                "credential_id: transaction_id=%s",
                transaction_id,
            )

            raise CredIssuerError(
                "G2P-VC-502",
                "CredIssuer did not return a credential_id.",
            )

        _logger.info(
            "Requesting CredIssuer PDF presentation: credential_id=%s",
            credential_id,
        )

        presentation = await self._create_pdf_presentation(
            credential_id=str(credential_id)
        )

        file_path = presentation.get("file_path")

        if not file_path:
            _logger.error(
                "CredIssuer PDF presentation did not contain file_path: "
                "credential_id=%s",
                credential_id,
            )

            raise CredIssuerError(
                "G2P-VC-502",
                "CredIssuer did not return a PDF file_path.",
            )

        file_name = (
            presentation.get("file_name")
            or f"credential-{credential_id}.pdf"
        )

        _logger.info(
            "CredIssuer PDF presentation created: credential_id=%s, "
            "file_name=%s",
            credential_id,
            file_name,
        )

        pdf_bytes = await self._download_pdf(file_path)

        _logger.info(
            "CredIssuer PDF downloaded successfully: credential_id=%s, "
            "file_name=%s, size=%d bytes",
            credential_id,
            file_name,
            len(pdf_bytes),
        )

        _logger.info(
            "CredIssuer issuance completed successfully: "
            "transaction_id=%s, credential_id=%s",
            transaction_id,
            credential_id,
        )

        return {
            "pdf_bytes": pdf_bytes,
            "file_name": file_name,
            "transaction_id": transaction_id,
            "credential_id": str(credential_id),
            "status": credential.get("status"),
        }

    async def _issue_credential(
        self,
        credential_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Submit credential data to CredIssuer."""

        url = (
            f"{self.base_url}/credentials/issue/client/bulk"
            f"?credential_template={self.template_id}"
            f"&mode_of_issuance=issue_and_notify"
        )

        payload = {
            "issuer_info": {
                "org_code": self.org_code,
                "email": self.issuer_email,
            },
            "issuer_credential_template_id": self.template_id,
            "credential_data": [credential_data],
        }

        _logger.info(
            "Calling CredIssuer issuance API: "
            "POST /credentials/issue/client/bulk, template_id=%s, "
            "mode_of_issuance=issue_and_notify",
            self.template_id,
        )

        _logger.debug(
            "CredIssuer issuance payload fields: %s",
            list(credential_data.keys()),
        )

        response = await self._request(
            method="POST",
            url=url,
            json=payload,
        )

        body = self._json(
            response,
            "CredIssuer issuance request failed",
        )

        _logger.info(
            "CredIssuer issuance API successful: transaction_id=%s, "
            "applied_count=%s, programme_name=%s",
            body.get("transaction_id"),
            body.get("applied_count"),
            body.get("programme_name"),
        )

        return body

    async def _get_issued_credential(
        self,
        transaction_id: str,
    ) -> Dict[str, Any]:
        """Retrieve the credential created by the issuance transaction."""

        url = (
            f"{self.base_url}/credentials/issued/{transaction_id}"
            "?offset=0"
            "&limit=10"
            "&statuses=Failed,Revoked,Issued,Notified,Printed,"
            "Printed_and_Notified"
        )

        _logger.info(
            "Calling CredIssuer transaction API: "
            "GET /credentials/issued/%s",
            transaction_id,
        )

        response = await self._request(
            method="GET",
            url=url,
        )

        body = self._json(
            response,
            "Could not retrieve the issued credential from CredIssuer",
        )

        results = body.get("results") or []

        _logger.info(
            "CredIssuer transaction API successful: transaction_id=%s, "
            "result_count=%d, status=%s",
            transaction_id,
            len(results),
            body.get("status"),
        )

        if results:
            credential = results[0]

            _logger.info(
                "CredIssuer transaction result: transaction_id=%s, "
                "credential_id=%s, credential_status=%s",
                transaction_id,
                credential.get("credential_id"),
                credential.get("status"),
            )

        return body

    async def _create_pdf_presentation(
        self,
        credential_id: str,
    ) -> Dict[str, Any]:
        """Ask CredIssuer to create a PDF presentation."""

        url = f"{self.base_url}/credentials/presentation"

        payload = {
            "credential_id": credential_id,
            "presentation_type": "pdf",
        }

        _logger.info(
            "Calling CredIssuer presentation API: "
            "POST /credentials/presentation, credential_id=%s",
            credential_id,
        )

        response = await self._request(
            method="POST",
            url=url,
            json=payload,
        )

        body = self._json(
            response,
            "Could not create the credential PDF presentation",
        )

        _logger.info(
            "CredIssuer presentation API successful: credential_id=%s, "
            "file_name=%s",
            credential_id,
            body.get("file_name"),
        )

        return body

    async def _download_pdf(self, file_path: str) -> bytes:
        """Download the PDF generated by CredIssuer."""

        _logger.info(
            "Downloading CredIssuer PDF from generated file URL"
        )

        started = time.monotonic()

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                response = await client.get(file_path)

        except httpx.TimeoutException as error:
            _logger.exception(
                "CredIssuer PDF download timed out"
            )

            raise CredIssuerError(
                "G2P-VC-504",
                "Could not download credential PDF: request timed out.",
            ) from error

        except httpx.HTTPError as error:
            _logger.exception(
                "Could not download CredIssuer PDF"
            )

            raise CredIssuerError(
                "G2P-VC-503",
                f"Could not download credential PDF: {error}",
            ) from error

        elapsed = time.monotonic() - started

        _logger.info(
            "CredIssuer PDF download response: status=%s, "
            "content_type=%s, size=%d bytes, elapsed=%.2fs",
            response.status_code,
            response.headers.get("content-type"),
            len(response.content),
            elapsed,
        )

        if response.status_code < 200 or response.status_code >= 300:
            raise CredIssuerError(
                "G2P-VC-503",
                f"CredIssuer PDF download failed with HTTP "
                f"{response.status_code}.",
            )

        content_type = response.headers.get(
            "content-type",
            "",
        ).lower()

        if "application/pdf" not in content_type:
            _logger.warning(
                "CredIssuer PDF URL returned unexpected content type: %s",
                content_type,
            )

        if not response.content:
            raise CredIssuerError(
                "CredIssuer returned an empty PDF.",
            )

        return response.content

    async def _request(
        self,
        method: str,
        url: str,
        json: Optional[Dict[str, Any]] = None,
    ) -> httpx.Response:
        """Make an authenticated request to CredIssuer."""

        token = self.token.strip()

        if not token.lower().startswith("bearer "):
            token = f"Bearer {token}"

        headers = {
            "Authorization": token,
            "Accept": "application/json",
        }

        if json is not None:
            headers["Content-Type"] = "application/json"

        safe_url = url.split("?", 1)[0]

        _logger.info(
            "CredIssuer API request started: method=%s, endpoint=%s",
            method,
            safe_url,
        )

        if json is not None:
            _logger.debug(
                "CredIssuer API request body: method=%s, endpoint=%s, body=%s",
                method,
                safe_url,
                self._safe_body(json),
            )

        started = time.monotonic()

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=json,
                )

        except httpx.TimeoutException as error:
            elapsed = time.monotonic() - started

            _logger.exception(
                "CredIssuer API timeout: method=%s, endpoint=%s, "
                "elapsed=%.2fs",
                method,
                safe_url,
                elapsed,
            )

            raise CredIssuerError(
                "G2P-VC-504",
                "CredIssuer request timed out.",
            ) from error

        except httpx.HTTPError as error:
            elapsed = time.monotonic() - started

            _logger.exception(
                "CredIssuer API HTTP error: method=%s, endpoint=%s, "
                "elapsed=%.2fs, error=%s",
                method,
                safe_url,
                elapsed,
                error,
            )

            raise CredIssuerError(
                "G2P-VC-503",
                f"CredIssuer request failed: {error}",
            ) from error

        elapsed = time.monotonic() - started

        _logger.info(
            "CredIssuer API response: method=%s, endpoint=%s, "
            "status=%s, elapsed=%.2fs",
            method,
            safe_url,
            response.status_code,
            elapsed,
        )

        if response.status_code < 200 or response.status_code >= 300:
            message = self._error_message(response)

            _logger.error(
                "CredIssuer API returned error: method=%s, endpoint=%s, "
                "status=%s, message=%s",
                method,
                safe_url,
                response.status_code,
                message,
            )

            raise CredIssuerError(
                "G2P-VC-502",
                message,
            )

        _logger.debug(
            "CredIssuer API request completed successfully: "
            "method=%s, endpoint=%s",
            method,
            safe_url,
        )

        return response

    @staticmethod
    def _safe_body(body: Any) -> Any:
        """Return a copy of a request body safe to write to logs.

        Masks fields that are large or sensitive (photo blobs, NID,
        email, auth tokens) so full request bodies can be logged at
        debug level without leaking PII or bloating log storage.
        """

        redact_keys = {
            "photo",
            "nid",
            "email",
            "token",
            "authorization",
        }

        def _scrub(value: Any) -> Any:
            if isinstance(value, dict):
                scrubbed = {}

                for key, val in value.items():
                    if key.lower() in redact_keys and val is not None:
                        if isinstance(val, str):
                            scrubbed[key] = f"<redacted:{len(val)} chars>"
                        else:
                            scrubbed[key] = "<redacted>"
                    else:
                        scrubbed[key] = _scrub(val)

                return scrubbed

            if isinstance(value, list):
                return [_scrub(item) for item in value]

            return value

        try:
            return _scrub(body)

        except Exception:
            return "<unavailable>"

    @staticmethod
    def _json(
        response: httpx.Response,
        context: str,
    ) -> Dict[str, Any]:
        """Decode a CredIssuer JSON response."""

        try:
            body = response.json()

        except ValueError as error:
            _logger.error(
                "%s: CredIssuer returned invalid JSON. status=%s",
                context,
                response.status_code,
            )

            raise CredIssuerError(
                "G2P-VC-502",
                f"{context}: CredIssuer returned invalid JSON.",
            ) from error

        if not isinstance(body, dict):
            _logger.error(
                "%s: CredIssuer returned unexpected response type: %s",
                context,
                type(body).__name__,
            )

            raise CredIssuerError(
                "G2P-VC-502",
                f"{context}: CredIssuer returned an unexpected response.",
            )

        return body

    @staticmethod
    def _error_message(response: httpx.Response) -> str:
        """Extract a useful error message without exposing credentials."""

        try:
            body = response.json()

            if isinstance(body, dict):
                for key in (
                    "message",
                    "error",
                    "detail",
                    "response_error_message",
                ):
                    value = body.get(key)

                    if value:
                        return str(value)

                errors = body.get("errors")

                if isinstance(errors, list) and errors:
                    first = errors[0]

                    if isinstance(first, dict):
                        return str(
                            first.get("message")
                            or first.get("detail")
                            or first
                        )

                    return str(first)

            return response.text[:500]

        except Exception:
            return response.text[:500]

    def _build_credential_data(
        self,
        claims: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Map registry claims into CredIssuer credential_data."""

        functional_record_id = str(
            claims.get("functionalRecordId") or ""
        )

        nid = functional_record_id

        if nid.startswith("FR-"):
            nid = nid[3:]

        credential_data: Dict[str, Any] = {
            "NID": nid,
            "email": claims.get("email"),
            "district": claims.get("district"),
            "farmerID": functional_record_id,
            "expiryDate": claims.get("expiryDate"),
            "subCountry": claims.get("subCountry"),
            "farmerGroup": claims.get("farmerGroup"),
            "issuanceDate": claims.get("issuanceDate"),
        }

        claim_photo = claims.get("photo")

        if claim_photo is not None:
            credential_data["photo"] = claim_photo
        elif self.default_photo:
            _logger.info(
                "Photo not present in claims for functionalRecordId=%s; "
                "using default photo from environment configuration.",
                claims.get("functionalRecordId"),
            )
            credential_data["photo"] = self.default_photo

        return {
            key: value
            for key, value in credential_data.items()
            if value is not None
        }
