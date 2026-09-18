import asyncio
import logging
from typing import Any, Dict, Optional

import httpx
from openg2p_fastapi_common.service import BaseService

from ..config import Settings
from .credissuer_service import CredIssuerError


_config = Settings.get_config()
_logger = logging.getLogger(_config.logging_default_logger_name)


class LandRecordCredIssuerService(BaseService):
    """
    Dedicated CredIssuer service for Land Record credentials.

    This service intentionally uses a separate credential_data schema
    from the Farmer Registry CredIssuer service.
    """

    # ------------------------------------------------------------------
    # Land Record CredIssuer configuration
    # ------------------------------------------------------------------

    CREDENTIAL_TEMPLATE_ID = "4584A8B4E479"

    # Configure this through application configuration/environment.
    # Do not commit a real bearer token to source control.
    CREDISSUER_TOKEN = "Bearer a7f3c9e12b84d65fa019e3c7b52a8d46f0c1be9"

    ORG_CODE = "FARME-OLL63"
    ISSUER_EMAIL = "rygimo@denipl.com"

    BASE_URL = "https://api.credissuer.com/api"

    # ------------------------------------------------------------------
    # Timing configuration
    # ------------------------------------------------------------------

    # Each individual HTTP request can take up to 5 minutes.
    DEFAULT_HTTP_TIMEOUT = 300

    # 60 attempts x 5 seconds = approximately 5 minutes of polling.
    TRANSACTION_MAX_ATTEMPTS = 60
    TRANSACTION_RETRY_DELAY = 5

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.base_url = (
            getattr(
                _config,
                "credential_api_base_url",
                None,
            )
            or self.BASE_URL
        ).rstrip("/")

        self.timeout = getattr(
            _config,
            "credential_api_http_timeout",
            self.DEFAULT_HTTP_TIMEOUT,
        )

        self.token = self.CREDISSUER_TOKEN
        self.template_id = self.CREDENTIAL_TEMPLATE_ID
        self.org_code = self.ORG_CODE
        self.issuer_email = self.ISSUER_EMAIL

    # ==================================================================
    # Public API
    # ==================================================================

    async def issue(
        self,
        claims: Dict[str, Any],
        credential_template: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Issue a Land Record credential through CredIssuer.

        Flow:
            1. Validate configuration
            2. Build Land Record credential_data
            3. Issue credential
            4. Poll transaction until credential is available
            5. Generate PDF presentation
            6. Download generated PDF
            7. Return PDF and issuance metadata
        """

        self._validate_configuration()

        credential_data = self._build_credential_data(claims)

        # Land Record always uses its dedicated template.
        template_id = self.template_id

        _logger.info(
            "Starting Land Record CredIssuer flow. "
            "template=%s, functionalRecordId=%s",
            template_id,
            claims.get("functionalRecordId"),
        )

        # --------------------------------------------------------------
        # 1. Issue credential
        # --------------------------------------------------------------

        issue_response = await self._issue_credential(
            credential_data=credential_data,
            credential_template=template_id,
        )

        transaction_id = issue_response.get("transaction_id")

        if not transaction_id:
            raise CredIssuerError(
                "G2P-VC-502",
                "CredIssuer issue API did not return transaction_id.",
            )

        _logger.info(
            "Land Record credential submitted to CredIssuer. "
            "transaction_id=%s",
            transaction_id,
        )

        # --------------------------------------------------------------
        # 2. Poll transaction until credential is available
        # --------------------------------------------------------------

        issued_credential = await self._get_issued_credential(
            transaction_id
        )

        credential_id = issued_credential.get("credential_id")

        if not credential_id:
            raise CredIssuerError(
                "G2P-VC-502",
                "CredIssuer transaction did not return credential_id.",
            )

        status = issued_credential.get("status")

        _logger.info(
            "Land Record credential available. "
            "transaction_id=%s, credential_id=%s, status=%s",
            transaction_id,
            credential_id,
            status,
        )

        # --------------------------------------------------------------
        # 3. Generate PDF presentation
        # --------------------------------------------------------------

        presentation_response = await self._create_pdf_presentation(
            credential_id
        )

        file_path = presentation_response.get("file_path")
        file_name = presentation_response.get("file_name")

        if not file_path:
            raise CredIssuerError(
                "G2P-VC-502",
                "CredIssuer presentation API did not return file_path.",
            )

        # --------------------------------------------------------------
        # 4. Download PDF
        # --------------------------------------------------------------

        pdf_bytes = await self._download_pdf(file_path)

        if not pdf_bytes:
            raise CredIssuerError(
                "G2P-VC-503",
                "CredIssuer PDF download returned empty content.",
            )

        _logger.info(
            "Land Record PDF downloaded successfully. "
            "transaction_id=%s, credential_id=%s, file_name=%s, size=%s",
            transaction_id,
            credential_id,
            file_name,
            len(pdf_bytes),
        )

        return {
            "pdf_bytes": pdf_bytes,
            "file_name": (
                file_name
                or f"Land-Record-Certificate-{credential_id}.pdf"
            ),
            "transaction_id": transaction_id,
            "credential_id": credential_id,
            "status": status,
        }

    # ==================================================================
    # Configuration
    # ==================================================================

    def _validate_configuration(self) -> None:
        """
        Validate required Land Record CredIssuer configuration.
        """

        if not self.token:
            raise CredIssuerError(
                "G2P-VC-502",
                "CredIssuer bearer token is not configured.",
            )

        if not self.template_id:
            raise CredIssuerError(
                "G2P-VC-502",
                (
                    "CredIssuer Land Record credential template "
                    "is not configured."
                ),
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

    # ==================================================================
    # Land Record credential data
    # ==================================================================

    def _build_credential_data(
        self,
        claims: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Build the Land Record credential_data object.

        Only functionalRecordId is dynamic.

        Mapping:
            functionalRecordId -> recordNo

        The following claims are intentionally NOT sent:

            fullName
            dateOfBirth
            gender

        All remaining Land Record values are hard-coded.
        """

        functional_record_id = claims.get("functionalRecordId")

        if not functional_record_id:
            raise CredIssuerError(
                "G2P-VC-502",
                "functionalRecordId is required for Land Record credential.",
            )

        credential_data = {
            "block": "Block 5",
            "email": "example@gmail.com",
            "parish": "Nakawa",
            "status": "Active",
            "RegDate": "2023-01-01T00:00:00.000Z",
            "country": "Uganda",
            "village": "Ntinda",
            "district": "Central",

            # Added fields from CredIssuer schema
            "farmName": "Bio Farm",

            # Dynamic field
            "recordNo": functional_record_id,

            "landTenure": "Freehold",
            "parcelArea": "500 sqm",
            "subCountry": "Kampala",
            "regProperty": "Residential",

            # Added field from CredIssuer schema
            "yearsOfFarming": "5 years",
        }

        _logger.debug(
            "Built Land Record credential data for functionalRecordId=%s",
            functional_record_id,
        )

        return credential_data

    # ==================================================================
    # Issue credential
    # ==================================================================

    async def _issue_credential(
        self,
        credential_data: Dict[str, Any],
        credential_template: str,
    ) -> Dict[str, Any]:
        """
        Call CredIssuer bulk credential issuance API.
        """

        endpoint = (
            f"{self.base_url}/credentials/issue/client/bulk"
        )

        params = {
            "credential_template": credential_template,
            "mode_of_issuance": "issue_and_notify",
        }

        payload = {
            "issuer_info": {
                "org_code": self.org_code,
                "email": self.issuer_email,
            },
            "issuer_credential_template_id": credential_template,
            "credential_data": [
                credential_data
            ],
        }

        _logger.info(
            "Calling CredIssuer Land Record issue API. "
            "template=%s",
            credential_template,
        )

        response = await self._request(
            method="POST",
            url=endpoint,
            params=params,
            json=payload,
        )

        if not isinstance(response, dict):
            raise CredIssuerError(
                "G2P-VC-502",
                "Unexpected response from CredIssuer issue API.",
            )

        return response

    # ==================================================================
    # Transaction polling
    # ==================================================================

    async def _get_issued_credential(
        self,
        transaction_id: str,
    ) -> Dict[str, Any]:
        """
        Poll CredIssuer until the issued credential becomes available.
        """

        endpoint = (
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

        for attempt in range(
            1,
            self.TRANSACTION_MAX_ATTEMPTS + 1,
        ):
            try:
                _logger.info(
                    "Checking CredIssuer transaction status. "
                    "transaction_id=%s, attempt=%s/%s",
                    transaction_id,
                    attempt,
                    self.TRANSACTION_MAX_ATTEMPTS,
                )

                response = await self._request(
                    method="GET",
                    url=endpoint,
                    params=params,
                )

                if not isinstance(response, dict):
                    raise CredIssuerError(
                        "G2P-VC-502",
                        "Unexpected transaction response from CredIssuer.",
                    )

                results = response.get("results") or []

                if results:
                    credential = results[0]

                    status = credential.get("status")

                    if status in {
                        "Failed",
                        "Revoked",
                    }:
                        raise CredIssuerError(
                            "G2P-VC-502",
                            (
                                "Land Record credential issuance failed. "
                                f"transaction_id={transaction_id}, "
                                f"status={status}, "
                                f"response={self._safe_body(response)}"
                            ),
                        )

                    credential_id = credential.get("credential_id")

                    if credential_id:
                        return credential

                transaction_status = response.get("status")

                if transaction_status in {
                    "Failed",
                    "Revoked",
                }:
                    raise CredIssuerError(
                        "G2P-VC-502",
                        (
                            "Land Record CredIssuer transaction failed. "
                            f"transaction_id={transaction_id}, "
                            f"status={transaction_status}"
                        ),
                    )

                if attempt < self.TRANSACTION_MAX_ATTEMPTS:
                    _logger.info(
                        "Credential not ready yet. "
                        "Waiting %s seconds before retry.",
                        self.TRANSACTION_RETRY_DELAY,
                    )

                    await asyncio.sleep(
                        self.TRANSACTION_RETRY_DELAY
                    )

            except CredIssuerError:
                raise

            except Exception as exc:
                _logger.warning(
                    "Error while polling CredIssuer transaction. "
                    "transaction_id=%s, attempt=%s/%s, error=%s",
                    transaction_id,
                    attempt,
                    self.TRANSACTION_MAX_ATTEMPTS,
                    exc,
                )

                if attempt < self.TRANSACTION_MAX_ATTEMPTS:
                    await asyncio.sleep(
                        self.TRANSACTION_RETRY_DELAY
                    )
                else:
                    raise CredIssuerError(
                        "G2P-VC-504",
                        (
                            "Timed out while waiting for CredIssuer "
                            "transaction to complete. "
                            f"transaction_id={transaction_id}"
                        ),
                    ) from exc

        raise CredIssuerError(
            "G2P-VC-504",
            (
                "Timed out waiting for CredIssuer credential. "
                f"transaction_id={transaction_id}"
            ),
        )

    # ==================================================================
    # PDF presentation
    # ==================================================================

    async def _create_pdf_presentation(
        self,
        credential_id: str,
    ) -> Dict[str, Any]:
        """
        Request a PDF presentation from CredIssuer.
        """

        endpoint = (
            f"{self.base_url}/credentials/presentation"
        )

        payload = {
            "credential_id": credential_id,
            "presentation_type": "pdf",
        }

        _logger.info(
            "Creating PDF presentation. credential_id=%s",
            credential_id,
        )

        response = await self._request(
            method="POST",
            url=endpoint,
            json=payload,
        )

        if not isinstance(response, dict):
            raise CredIssuerError(
                "G2P-VC-502",
                (
                    "Unexpected response from CredIssuer "
                    "presentation API."
                ),
            )

        return response

    # ==================================================================
    # PDF download
    # ==================================================================

    async def _download_pdf(
        self,
        file_path: str,
    ) -> bytes:
        """
        Download the generated PDF from CredIssuer CDN.
        """

        _logger.info(
            "Downloading Land Record PDF from CredIssuer CDN."
        )

        try:
            timeout = httpx.Timeout(
                self.timeout,
                connect=self.timeout,
            )

            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=True,
            ) as client:

                response = await client.get(file_path)

                response.raise_for_status()

                return response.content

        except httpx.TimeoutException as exc:
            _logger.error(
                "Timed out downloading CredIssuer PDF."
            )

            raise CredIssuerError(
                "G2P-VC-504",
                "Timed out downloading Land Record PDF.",
            ) from exc

        except httpx.HTTPStatusError as exc:
            _logger.error(
                "CredIssuer PDF download failed. status=%s",
                exc.response.status_code,
            )

            raise CredIssuerError(
                "G2P-VC-503",
                (
                    "Failed to download Land Record PDF from "
                    "CredIssuer. "
                    f"HTTP {exc.response.status_code}"
                ),
            ) from exc

        except httpx.HTTPError as exc:
            _logger.error(
                "CredIssuer PDF download HTTP error: %s",
                exc,
            )

            raise CredIssuerError(
                "G2P-VC-503",
                "HTTP error while downloading Land Record PDF.",
            ) from exc

    # ==================================================================
    # Generic HTTP request helper
    # ==================================================================

    async def _request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Execute an authenticated CredIssuer HTTP request.

        Authorization header is deliberately not logged.
        """

        token = str(self.token).strip()

        if token.lower().startswith("bearer "):
            token = token[7:].strip()

        if not token:
            raise CredIssuerError(
                "G2P-VC-502",
                "CredIssuer API token is empty.",
            )

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        _logger.info(
            "CredIssuer request: method=%s, url=%s",
            method,
            url,
        )

        try:
            timeout = httpx.Timeout(
                self.timeout,
                connect=self.timeout,
            )

            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=True,
            ) as client:

                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    json=json,
                )

                if response.is_error:
                    message = self._error_message(response)

                    _logger.error(
                        "CredIssuer API error. "
                        "status=%s, message=%s",
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
                        (
                            "CredIssuer API returned HTTP "
                            f"{response.status_code}: {message}"
                        ),
                    )

                return self._json(response)

        except CredIssuerError:
            raise

        except httpx.TimeoutException as exc:
            _logger.error(
                "CredIssuer API request timed out. "
                "method=%s, url=%s, timeout=%s",
                method,
                url,
                self.timeout,
            )

            raise CredIssuerError(
                "G2P-VC-504",
                (
                    "CredIssuer API request timed out after "
                    f"{self.timeout} seconds"
                ),
            ) from exc

        except httpx.HTTPError as exc:
            _logger.error(
                "CredIssuer HTTP error. "
                "method=%s, url=%s, error=%s",
                method,
                url,
                exc,
            )

            raise CredIssuerError(
                "G2P-VC-503",
                f"CredIssuer HTTP error: {exc}",
            ) from exc

        except Exception as exc:
            _logger.exception(
                "Unexpected CredIssuer error. "
                "method=%s, url=%s",
                method,
                url,
            )

            raise CredIssuerError(
                "G2P-VC-503",
                f"Unexpected CredIssuer error: {exc}",
            ) from exc

    # ==================================================================
    # Response helpers
    # ==================================================================

    def _json(
        self,
        response: httpx.Response,
    ) -> Dict[str, Any]:
        """
        Safely parse JSON response.
        """

        try:
            body = response.json()

            if isinstance(body, dict):
                return body

            return {
                "data": body
            }

        except ValueError as exc:
            raise CredIssuerError(
                "G2P-VC-502",
                "CredIssuer returned a non-JSON response.",
            ) from exc

    def _safe_body(
        self,
        body: Any,
    ) -> str:
        """
        Safely format response body for logs/errors.

        Never include the Authorization header here.
        """

        try:
            text = str(body)

            if len(text) > 2000:
                return text[:2000] + "...<truncated>"

            return text

        except Exception:
            return "<unable to format response body>"

    def _error_message(
        self,
        response: httpx.Response,
    ) -> str:
        """
        Extract a useful error message from CredIssuer response.
        """

        try:
            body = response.json()

            if isinstance(body, dict):
                for key in (
                    "message",
                    "error",
                    "detail",
                    "description",
                ):
                    value = body.get(key)

                    if value:
                        return str(value)

                return self._safe_body(body)

            return self._safe_body(body)

        except ValueError:
            try:
                return response.text[:2000]
            except Exception:
                return "<unable to read error response>"
