import asyncio
import logging
import os
import time
from datetime import datetime, timezone
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
        1. Validate and prepare credential data.
        2. Submit credential data for issuance.
        3. Retrieve the issued credential using transaction_id.
        4. Create a PDF presentation.
        5. Download the generated PDF.

    Credential date/default values:
        issuanceDate = current UTC timestamp
        expiryDate   = one calendar year from current UTC timestamp
        subCountry   = Central
        farmerGroup  = Green Farmers Co-op

    Hardcoded credential values:
        NID      = functionalRecordId
        email    = nudili@denipl.net
        district = Ganlulu

    Default photo:
        Loaded from CREDENTIAL_API_DEFAULT_PHOTO_PATH, which in the
        Kubernetes Deployment is /etc/credissuer/photo.b64 and is expected
        to be provided by the credissuer-default-photo Secret.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.base_url = (
            getattr(_config, "credential_api_base_url", None)
            or "https://api.credissuer.com/api"
        ).rstrip("/")

        self.token = getattr(
            _config,
            "credential_api_token",
            None,
        )

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

        self.default_photo = self._load_default_photo()

        if not self.token:
            _logger.warning(
                "CredIssuer API token is not configured."
            )

        if not self.template_id:
            _logger.warning(
                "CredIssuer credential template is not configured."
            )

        if not self.org_code:
            _logger.warning(
                "CredIssuer organization code is not configured."
            )

        if not self.issuer_email:
            _logger.warning(
                "CredIssuer issuer email is not configured."
            )

        if not self.default_photo:
            _logger.info(
                "No default photo configured. "
                "Photo will only be sent when supplied in claims."
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
        """Load fallback photo from the Kubernetes Secret-mounted file,
        environment, or application config.
        """

        photo_path = os.environ.get(
            "CREDENTIAL_API_DEFAULT_PHOTO_PATH"
        )

        if photo_path:
            try:
                with open(
                    photo_path,
                    "r",
                    encoding="utf-8",
                ) as fh:
                    content = fh.read().strip()

                if content:
                    _logger.info(
                        "Loaded default photo from file: %s",
                        photo_path,
                    )
                    return content

                _logger.warning(
                    "Default photo file is empty: %s",
                    photo_path,
                )

            except OSError:
                _logger.exception(
                    "Could not read default photo file: %s",
                    photo_path,
                )

        env_photo = os.environ.get(
            "CREDENTIAL_API_DEFAULT_PHOTO"
        )

        if env_photo:
            return env_photo.strip()

        config_photo = getattr(
            _config,
            "credential_api_default_photo",
            None,
        )

        if config_photo:
            return str(config_photo).strip()

        return None

    async def issue(
        self,
        claims: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Issue a credential and return generated PDF information."""

        functional_record_id = claims.get(
            "functionalRecordId"
        )

        _logger.info(
            "Starting CredIssuer credential issuance: "
            "functionalRecordId=%s",
            functional_record_id,
        )

        self._validate_configuration()

        credential_data = self._build_credential_data(
            claims
        )

        _logger.info(
            "CredIssuer credential data prepared: fields=%s",
            list(credential_data.keys()),
        )

        _logger.debug(
            "CredIssuer credential data: %s",
            self._safe_body(credential_data),
        )

        transaction = await self._issue_credential(
            credential_data
        )

        transaction_id = transaction.get(
            "transaction_id"
        )

        if not transaction_id:
            _logger.error(
                "CredIssuer issuance response did not contain "
                "transaction_id: response=%s",
                self._safe_body(transaction),
            )

            raise CredIssuerError(
                "G2P-VC-502",
                "CredIssuer did not return a transaction_id.",
            )

        _logger.info(
            "CredIssuer issuance accepted: transaction_id=%s",
            transaction_id,
        )

        issued = await self._get_issued_credential(
            str(transaction_id)
        )

        results = issued.get("results") or []

        if not results:
            raise CredIssuerError(
                "G2P-VC-502",
                (
                    "CredIssuer did not return a credential for "
                    f"transaction {transaction_id}."
                ),
            )

        credential = results[0]

        status = str(
            credential.get("status") or ""
        ).strip().lower()

        _logger.info(
            "CredIssuer credential retrieved: "
            "transaction_id=%s, credential_id=%s, status=%s",
            transaction_id,
            credential.get("credential_id"),
            credential.get("status"),
        )

        if status in {
            "failed",
            "revoked",
        }:
            raise CredIssuerError(
                "G2P-VC-502",
                (
                    "CredIssuer returned credential status: "
                    f"{credential.get('status')}."
                ),
            )

        credential_id = credential.get(
            "credential_id"
        )

        if not credential_id:
            raise CredIssuerError(
                "G2P-VC-502",
                "CredIssuer did not return a credential_id.",
            )

        _logger.info(
            "Requesting CredIssuer PDF presentation: "
            "credential_id=%s",
            credential_id,
        )

        presentation = await self._create_pdf_presentation(
            str(credential_id)
        )

        file_path = presentation.get(
            "file_path"
        )

        if not file_path:
            raise CredIssuerError(
                "G2P-VC-502",
                "CredIssuer did not return a PDF file_path.",
            )

        file_name = (
            presentation.get("file_name")
            or f"credential-{credential_id}.pdf"
        )

        pdf_bytes = await self._download_pdf(
            str(file_path)
        )

        _logger.info(
            "CredIssuer PDF downloaded successfully: "
            "credential_id=%s, file_name=%s, size=%d bytes",
            credential_id,
            file_name,
            len(pdf_bytes),
        )

        return {
            "pdf_bytes": pdf_bytes,
            "file_name": file_name,
            "transaction_id": str(transaction_id),
            "credential_id": str(credential_id),
            "status": credential.get("status"),
        }

    def _validate_configuration(self) -> None:
        """Validate required CredIssuer configuration."""

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

        if not self.org_code:
            raise CredIssuerError(
                "G2P-VC-502",
                "CredIssuer organization code is not configured.",
            )

        if not self.issuer_email:
            raise CredIssuerError(
                "G2P-VC-502",
                "CredIssuer issuer email is not configured.",
            )

    async def _issue_credential(
        self,
        credential_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Submit credential data to CredIssuer."""

        url = (
            f"{self.base_url}/credentials/issue/client/bulk"
        )

        params = {
            "credential_template": self.template_id,
            "mode_of_issuance": "issue_and_notify",
        }

        payload = {
            "issuer_info": {
                "org_code": self.org_code,
                "email": self.issuer_email,
            },
            "issuer_credential_template_id": self.template_id,
            "credential_data": [
                credential_data,
            ],
        }

        _logger.info(
            "Calling CredIssuer issuance API: "
            "POST /credentials/issue/client/bulk, "
            "template_id=%s, mode_of_issuance=%s",
            self.template_id,
            params["mode_of_issuance"],
        )

        _logger.debug(
            "CredIssuer issuance payload: %s",
            self._safe_body(payload),
        )

        response = await self._request(
            method="POST",
            url=url,
            params=params,
            json=payload,
        )

        body = self._json(
            response,
            "CredIssuer issuance request failed",
        )

        _logger.info(
            "CredIssuer issuance API successful: "
            "transaction_id=%s, applied_count=%s, "
            "programme_name=%s",
            body.get("transaction_id"),
            body.get("applied_count"),
            body.get("programme_name"),
        )

        return body

    async def _get_issued_credential(
        self,
        transaction_id: str,
    ) -> Dict[str, Any]:
        """Retrieve issued credential with retry handling."""

        url = (
            f"{self.base_url}/credentials/issued/"
            f"{transaction_id}"
        )

        params = {
            "offset": 0,
            "limit": 10,
            "statuses": (
                "Failed,Revoked,Issued,Notified,"
                "Printed,Printed_and_Notified"
            ),
        }

        max_retries = 5
        retry_delay = 2

        last_body: Optional[Dict[str, Any]] = None

        for attempt in range(1, max_retries + 1):
            _logger.info(
                "Calling CredIssuer transaction API "
                "(attempt %d/%d): GET /credentials/issued/%s",
                attempt,
                max_retries,
                transaction_id,
            )

            try:
                response = await self._request(
                    method="GET",
                    url=url,
                    params=params,
                )

                body = self._json(
                    response,
                    (
                        "Could not retrieve the issued "
                        "credential from CredIssuer"
                    ),
                )

                last_body = body

                results = body.get("results") or []

                _logger.info(
                    "CredIssuer transaction API response: "
                    "transaction_id=%s, result_count=%d, "
                    "status=%s",
                    transaction_id,
                    len(results),
                    body.get("status"),
                )

                if results:
                    credential = results[0]

                    _logger.info(
                        "CredIssuer transaction result: "
                        "transaction_id=%s, credential_id=%s, "
                        "credential_status=%s",
                        transaction_id,
                        credential.get("credential_id"),
                        credential.get("status"),
                    )

                    return body

                if attempt < max_retries:
                    _logger.warning(
                        "CredIssuer has not produced a credential yet: "
                        "transaction_id=%s, retrying in %ss",
                        transaction_id,
                        retry_delay,
                    )

                    await asyncio.sleep(
                        retry_delay
                    )

            except CredIssuerError as error:
                message = str(error.message)

                retryable = (
                    "Credential Transaction Log not found"
                    in message
                    or "not found"
                    in message.lower()
                )

                if retryable and attempt < max_retries:
                    _logger.warning(
                        "CredIssuer transaction is not ready: "
                        "transaction_id=%s, error=%s, "
                        "retrying in %ss",
                        transaction_id,
                        message,
                        retry_delay,
                    )

                    await asyncio.sleep(
                        retry_delay
                    )
                    continue

                raise

        if last_body is not None:
            raise CredIssuerError(
                "G2P-VC-502",
                (
                    "CredIssuer did not produce the credential "
                    f"after {max_retries} attempts for transaction "
                    f"{transaction_id}."
                ),
            )

        raise CredIssuerError(
            "G2P-VC-502",
            (
                "Could not retrieve the credential transaction "
                f"for {transaction_id}."
            ),
        )

    async def _create_pdf_presentation(
        self,
        credential_id: str,
    ) -> Dict[str, Any]:
        """Ask CredIssuer to create a PDF presentation."""

        url = (
            f"{self.base_url}/credentials/presentation"
        )

        payload = {
            "credential_id": credential_id,
            "presentation_type": "pdf",
        }

        _logger.info(
            "Calling CredIssuer presentation API: "
            "POST /credentials/presentation, "
            "credential_id=%s",
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

        return body

    async def _download_pdf(
        self,
        file_path: str,
    ) -> bytes:
        """Download the PDF generated by CredIssuer."""

        _logger.info(
            "Downloading CredIssuer PDF"
        )

        started = time.monotonic()

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                response = await client.get(
                    file_path
                )

        except httpx.TimeoutException as error:
            _logger.exception(
                "CredIssuer PDF download timed out"
            )

            raise CredIssuerError(
                "G2P-VC-504",
                (
                    "Could not download credential PDF: "
                    "request timed out."
                ),
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
            "CredIssuer PDF download response: "
            "status=%s, content_type=%s, size=%d bytes, "
            "elapsed=%.2fs",
            response.status_code,
            response.headers.get("content-type"),
            len(response.content),
            elapsed,
        )

        if (
            response.status_code < 200
            or response.status_code >= 300
        ):
            raise CredIssuerError(
                "G2P-VC-503",
                (
                    "CredIssuer PDF download failed with "
                    f"HTTP {response.status_code}."
                ),
            )

        if not response.content:
            raise CredIssuerError(
                "G2P-VC-503",
                "CredIssuer returned an empty PDF.",
            )

        return response.content

    async def _request(
        self,
        method: str,
        url: str,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> httpx.Response:
        """Make an authenticated request to CredIssuer."""

        if not self.token:
            raise CredIssuerError(
                "G2P-VC-502",
                "CredIssuer API token is not configured.",
            )

        token = str(
            self.token
        ).strip()

        if not token:
            raise CredIssuerError(
                "G2P-VC-502",
                "CredIssuer API token is empty.",
            )

        if not token.lower().startswith("bearer "):
            token = f"Bearer {token}"

        headers = {
            "Authorization": token,
            "Accept": "application/json",
        }

        if json is not None:
            headers["Content-Type"] = (
                "application/json"
            )

        safe_url = url.split(
            "?",
            1,
        )[0]

        _logger.info(
            "CredIssuer API request started: "
            "method=%s, endpoint=%s",
            method,
            safe_url,
        )

        if params:
            _logger.debug(
                "CredIssuer API query parameters: %s",
                self._safe_body(params),
            )

        if json is not None:
            _logger.debug(
                "CredIssuer API request body: %s",
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
                    params=params,
                    headers=headers,
                    json=json,
                )

        except httpx.TimeoutException as error:
            elapsed = time.monotonic() - started

            _logger.exception(
                "CredIssuer API timeout: method=%s, "
                "endpoint=%s, elapsed=%.2fs",
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
                "CredIssuer API HTTP error: method=%s, "
                "endpoint=%s, elapsed=%.2fs, error=%s",
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
            "CredIssuer API response: method=%s, "
            "endpoint=%s, status=%s, elapsed=%.2fs",
            method,
            safe_url,
            response.status_code,
            elapsed,
        )

        if (
            response.status_code < 200
            or response.status_code >= 300
        ):
            message = self._error_message(
                response
            )

            _logger.error(
                "CredIssuer API returned error: "
                "method=%s, endpoint=%s, status=%s, "
                "message=%s",
                method,
                safe_url,
                response.status_code,
                message,
            )

            code = (
                "G2P-VC-502"
                if response.status_code == 400
                else "G2P-VC-503"
            )

            raise CredIssuerError(
                code,
                message,
            )

        return response

    @staticmethod
    def _safe_body(
        body: Any,
    ) -> Any:
        """Return a log-safe copy of a request/response body."""

        redact_keys = {
            "photo",
            "nid",
            "email",
            "token",
            "authorization",
            "dateofbirth",
            "fullname",
        }

        def _scrub(
            value: Any,
        ) -> Any:
            if isinstance(value, dict):
                result = {}

                for key, val in value.items():
                    normalized_key = str(
                        key
                    ).lower()

                    if (
                        normalized_key
                        in redact_keys
                        and val is not None
                    ):
                        if isinstance(
                            val,
                            str,
                        ):
                            result[key] = (
                                f"<redacted:{len(val)} chars>"
                            )
                        else:
                            result[key] = "<redacted>"
                    else:
                        result[key] = _scrub(
                            val
                        )

                return result

            if isinstance(value, list):
                return [
                    _scrub(item)
                    for item in value
                ]

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
                "%s: CredIssuer returned invalid JSON. "
                "status=%s",
                context,
                response.status_code,
            )

            raise CredIssuerError(
                "G2P-VC-502",
                (
                    f"{context}: CredIssuer returned "
                    "invalid JSON."
                ),
            ) from error

        if not isinstance(
            body,
            dict,
        ):
            raise CredIssuerError(
                "G2P-VC-502",
                (
                    f"{context}: CredIssuer returned an "
                    "unexpected response."
                ),
            )

        return body

    @staticmethod
    def _error_message(
        response: httpx.Response,
    ) -> str:
        """Extract useful error details from CredIssuer."""

        try:
            body = response.json()

            if isinstance(
                body,
                dict,
            ):
                response_header = body.get(
                    "response_header"
                )

                if isinstance(
                    response_header,
                    dict,
                ):
                    error_code = response_header.get(
                        "response_error_code"
                    )
                    error_message = response_header.get(
                        "response_error_message"
                    )

                    if error_code and error_message:
                        return (
                            f"{error_code}: "
                            f"{error_message}"
                        )

                    if error_message:
                        return str(
                            error_message
                        )

                    if error_code:
                        return str(
                            error_code
                        )

                for key in (
                    "message",
                    "error",
                    "detail",
                    "response_error_message",
                ):
                    value = body.get(
                        key
                    )

                    if value:
                        return str(
                            value
                        )

                errors = body.get(
                    "errors"
                )

                if isinstance(
                    errors,
                    list,
                ) and errors:
                    first = errors[0]

                    if isinstance(
                        first,
                        dict,
                    ):
                        return str(
                            first.get("message")
                            or first.get("detail")
                            or first
                        )

                    return str(
                        first
                    )

            text = response.text.strip()

            if text:
                return text[:1000]

            return (
                f"CredIssuer returned HTTP "
                f"{response.status_code}."
            )

        except Exception:
            text = response.text.strip()

            if text:
                return text[:1000]

            return (
                f"CredIssuer returned HTTP "
                f"{response.status_code}."
            )

    def _build_credential_data(
        self,
        claims: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Map registry claims into the CredIssuer template.

        Hardcoded/requested values:
            NID          = functionalRecordId
            email        = nudili@denipl.net
            district     = Ganlulu
            subCountry   = Central
            farmerGroup  = Green Farmers Co-op
            issuanceDate = current UTC timestamp
            expiryDate   = one calendar year from issuance
        """

        # ------------------------------------------------------------------
        # Functional Record ID
        # ------------------------------------------------------------------
        functional_record_id = self._required_string(
            claims,
            "functionalRecordId",
        )

        # ------------------------------------------------------------------
        # NID
        # ------------------------------------------------------------------
        # Requested behavior:
        # NID must be exactly the functionalRecordId.
        nid = functional_record_id

        # ------------------------------------------------------------------
        # Hardcoded email and district
        # ------------------------------------------------------------------
        email = "nudili@denipl.net"
        district = "Ganlulu"

        # ------------------------------------------------------------------
        # Farmer ID
        # ------------------------------------------------------------------
        # Keep existing behavior. If farmerID is not present, use
        # functionalRecordId.
        farmer_id = (
            self._optional_string(
                claims,
                "farmerID",
            )
            or self._optional_string(
                claims,
                "farmerId",
            )
            or self._optional_string(
                claims,
                "farmer_id",
            )
            or functional_record_id
        )

        # ------------------------------------------------------------------
        # Issuance date
        # ------------------------------------------------------------------
        # Example:
        # 2026-09-15T18:15:30.123Z
        issuance_date = self._current_utc_iso()

        # ------------------------------------------------------------------
        # Expiry date
        # ------------------------------------------------------------------
        # One calendar year after issuance.
        expiry_date = self._one_year_from_now_iso()

        # ------------------------------------------------------------------
        # Hardcoded country/group
        # ------------------------------------------------------------------
        sub_country = "Central"
        farmer_group = "Green Farmers Co-op"

        # ------------------------------------------------------------------
        # Credential data
        # ------------------------------------------------------------------
        credential_data: Dict[str, Any] = {
            "NID": nid,
            "email": email,
            "district": district,
            "farmerID": farmer_id,
            "expiryDate": expiry_date,
            "subCountry": sub_country,
            "farmerGroup": farmer_group,
            "issuanceDate": issuance_date,
        }

        # ------------------------------------------------------------------
        # Photo
        # ------------------------------------------------------------------
        # Priority:
        #   1. Photo supplied in claims
        #   2. Kubernetes Secret-mounted default photo
        #
        # CREDENTIAL_API_DEFAULT_PHOTO_PATH should point to:
        # /etc/credissuer/photo.b64
        claim_photo = claims.get(
            "photo"
        )

        if claim_photo:
            credential_data["photo"] = (
                self._build_photo_value(
                    claim_photo,
                    "credential_photo.png",
                )
            )

        elif self.default_photo:
            _logger.info(
                "Photo not present in claims for "
                "functionalRecordId=%s; using default "
                "photo from CREDENTIAL_API_DEFAULT_PHOTO_PATH.",
                functional_record_id,
            )

            credential_data["photo"] = (
                self._build_photo_value(
                    self.default_photo,
                    "default_photo.png",
                )
            )

        else:
            _logger.warning(
                "No photo available for "
                "functionalRecordId=%s.",
                functional_record_id,
            )

        # ------------------------------------------------------------------
        # Remove empty values
        # ------------------------------------------------------------------
        credential_data = {
            key: value
            for key, value in credential_data.items()
            if value is not None
            and value != ""
        }

        # ------------------------------------------------------------------
        # Validate required fields
        # ------------------------------------------------------------------
        required_template_fields = {
            "NID",
            "email",
            "district",
            "farmerID",
            "expiryDate",
            "subCountry",
            "farmerGroup",
            "issuanceDate",
        }

        missing_fields = sorted(
            field
            for field in required_template_fields
            if not credential_data.get(field)
        )

        if missing_fields:
            _logger.error(
                "CredIssuer credential data is incomplete: "
                "functionalRecordId=%s, missing_fields=%s, "
                "available_claims=%s",
                functional_record_id,
                missing_fields,
                sorted(
                    str(key)
                    for key in claims.keys()
                ),
            )

            raise CredIssuerError(
                "G2P-VC-502",
                (
                    "Invalid credential data before calling "
                    "CredIssuer. Missing required template "
                    f"fields: {', '.join(missing_fields)}."
                ),
            )

        _logger.info(
            "CredIssuer credential dates/defaults prepared: "
            "functionalRecordId=%s, issuanceDate=%s, "
            "expiryDate=%s, subCountry=%s, farmerGroup=%s, "
            "nid_source=functionalRecordId, "
            "email_source=hardcoded, "
            "district_source=hardcoded, "
            "photo_configured=%s",
            functional_record_id,
            issuance_date,
            expiry_date,
            sub_country,
            farmer_group,
            "photo" in credential_data,
        )

        return credential_data

    @staticmethod
    def _current_utc_iso() -> str:
        """Return current UTC timestamp as YYYY-MM-DDTHH:MM:SS.mmmZ."""

        now = datetime.now(
            timezone.utc
        )

        return (
            now.strftime(
                "%Y-%m-%dT%H:%M:%S."
            )
            + f"{now.microsecond // 1000:03d}Z"
        )

    @staticmethod
    def _one_year_from_now_iso() -> str:
        """Return current UTC timestamp plus one calendar year.

        If today is February 29 and the next year is not a leap year,
        February 28 is used.
        """

        now = datetime.now(
            timezone.utc
        )

        try:
            expiry = now.replace(
                year=now.year + 1
            )

        except ValueError:
            # February 29 -> February 28 in a non-leap year.
            expiry = now.replace(
                year=now.year + 1,
                month=2,
                day=28,
            )

        return (
            expiry.strftime(
                "%Y-%m-%dT%H:%M:%S."
            )
            + f"{expiry.microsecond // 1000:03d}Z"
        )

    @staticmethod
    def _required_string(
        claims: Dict[str, Any],
        field: str,
    ) -> str:
        """Get a required non-empty string claim."""

        value = claims.get(
            field
        )

        if value is None:
            raise CredIssuerError(
                "G2P-VC-502",
                (
                    f"Missing required registry claim: "
                    f"{field}."
                ),
            )

        value = str(
            value
        ).strip()

        if not value:
            raise CredIssuerError(
                "G2P-VC-502",
                (
                    f"Required registry claim is empty: "
                    f"{field}."
                ),
            )

        return value

    @staticmethod
    def _optional_string(
        claims: Dict[str, Any],
        field: str,
    ) -> Optional[str]:
        """Get an optional string claim."""

        value = claims.get(
            field
        )

        if value is None:
            return None

        if isinstance(
            value,
            str,
        ):
            value = value.strip()

            return value or None

        return str(
            value
        ).strip() or None

    @staticmethod
    def _build_photo_value(
        photo: Any,
        filename: str,
    ) -> Any:
        """Convert a photo into the expected base64 attachment structure."""

        if isinstance(
            photo,
            list,
        ):
            return photo

        if isinstance(
            photo,
            dict,
        ):
            return photo

        if not isinstance(
            photo,
            str,
        ):
            raise CredIssuerError(
                "G2P-VC-502",
                "Credential photo must be a string or object.",
            )

        photo = photo.strip()

        if not photo:
            raise CredIssuerError(
                "G2P-VC-502",
                "Credential photo cannot be empty.",
            )

        # Keep an existing data URI unchanged.
        if photo.startswith(
            "data:"
        ):
            data_url = photo

            # Extract MIME type from the data URI.
            mime_type = (
                photo[5:].split(
                    ";",
                    1,
                )[0]
                or "image/png"
            )

        else:
            data_url = (
                "data:image/png;base64,"
                f"{photo}"
            )
            mime_type = "image/png"

        photo_size = len(
            photo.encode(
                "utf-8"
            )
        )

        return [
            {
                "storage": "base64",
                "name": filename,
                "url": data_url,
                "size": photo_size,
                "type": mime_type,
                "originalName": filename,
                "hash": "",
            }
        ]
