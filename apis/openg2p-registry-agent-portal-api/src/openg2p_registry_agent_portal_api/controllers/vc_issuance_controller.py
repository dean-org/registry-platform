import logging
from typing import Optional

from fastapi import Request, Response
from iam_core.user_auth.decorators import require_permissions
from openg2p_fastapi_common.controller import BaseController

from ..audit_context import set_audit
from ..config import Settings
from ..helpers import RequestResponseHelper
from ..schemas import (
    AuthenticationStatusRequest,
    AuthenticationStatusResponse,
    AuthenticationStatusResponseBody,
    AuthenticationStatusResultPayload,
    IssueVcRequest,
    IssueVcResponse,
    IssueVcResponseBody,
    LookupBeneficiaryRequest,
    LookupBeneficiaryResponse,
    LookupBeneficiaryResponseBody,
    LookupBeneficiaryResultPayload,
    StartAuthenticationRequest,
    StartAuthenticationResponse,
    StartAuthenticationResponseBody,
    StartAuthenticationResultPayload,
    VcTypeInfo,
    VcTypesResponse,
    VcTypesResponseBody,
    VcTypesResultPayload,
)
from ..services import (
    BeneficiaryAuthError,
    BeneficiaryAuthService,
    CertifyIssuanceError,
    CertifyIssuanceService,
    IssuanceLogService,
    PdfRenderService,
    RegistryLookupError,
    RegistryLookupService,
)
from ..services.registry_lookup_service import RECORD_NAME_COLUMN, REGISTER_ID_COLUMN, FOUNDATIONAL_ID_COLUMN
from openg2p_registry_core.models import VcIssuanceStatusEnum

_config = Settings.get_config()
_logger = logging.getLogger(_config.logging_default_logger_name)

# The permission an agent must hold. Agents are a distinct audience from staff:
# a separate Keycloak realm and a separate portal, so holding staff permissions
# grants nothing here.
ISSUE_PERMISSION = "register:issue_credential"


class VcIssuanceController(BaseController):
    """Agent-facing verifiable credential issuance.

    The flow is deliberately four calls rather than one. The beneficiary has to
    go and authenticate at eSignet in between, which the agent's client cannot
    do inline, and splitting it lets the client poll and show progress:

        lookup_beneficiary → start_authentication → authentication_status → issue

    Both parties must be authenticated for anything to be issued: the **agent**
    by the token on every call, the **beneficiary** by a successful, still-valid
    eSignet authentication checked at the point of issue.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.router.tags += ["Agent Portal - VC Issuance"]
        self.router.prefix += "/agent_portal/vc"

        self.registry_lookup_service = RegistryLookupService.get_component()
        self.beneficiary_auth_service = BeneficiaryAuthService.get_component()
        self.certify_issuance_service = CertifyIssuanceService.get_component()
        self.pdf_render_service = PdfRenderService.get_component()
        self.issuance_log_service = IssuanceLogService.get_component()
        self.helper = RequestResponseHelper.get_component()

        self.router.add_api_route(
            "/get_vc_types",
            self.get_vc_types,
            responses={200: {"model": VcTypesResponse}},
            methods=["POST"],
        )
        self.router.add_api_route(
            "/lookup_beneficiary",
            self.lookup_beneficiary,
            responses={200: {"model": LookupBeneficiaryResponse}},
            methods=["POST"],
        )
        self.router.add_api_route(
            "/start_authentication",
            self.start_authentication,
            responses={200: {"model": StartAuthenticationResponse}},
            methods=["POST"],
        )
        self.router.add_api_route(
            "/authentication_status",
            self.authentication_status,
            responses={200: {"model": AuthenticationStatusResponse}},
            methods=["POST"],
        )
        self.router.add_api_route(
            "/issue",
            self.issue,
            responses={
                200: {
                    "content": {"application/pdf": {}},
                    "description": "The printable credential.",
                },
                400: {"model": IssueVcResponse},
            },
            methods=["POST"],
        )

        self.router.add_api_route(
            "/issue/credissuer",
            self.issue_credissuer,
            responses={
                200: {
                    "content": {"application/pdf": {}},
                    "description": "The printable credential issued through CredIssuer.",
                },
                400: {"model": IssueVcResponse},
            },
            methods=["POST"],
        )

    # ── helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _agent_id(request: Request) -> str:
        auth = getattr(request.state, "auth", None)
        return (getattr(auth, "sub", None) or getattr(auth, "name", None) or "unknown") if auth else "unknown"

    @staticmethod
    def _register_id(payload_register_id: Optional[str], row: Optional[dict] = None) -> str:
        if payload_register_id:
            return payload_register_id
        if row and row.get(REGISTER_ID_COLUMN):
            return str(row[REGISTER_ID_COLUMN])
        return _config.vc_register_id

    # ── routes ────────────────────────────────────────────────────────────────
    @require_permissions({ISSUE_PERMISSION})
    async def get_vc_types(self, request: Request) -> VcTypesResponse:
        """What this deployment can issue — drives the agent's type selector."""
        set_audit(request, action="list_vc_types", resource_type="vc_definition")
        types = [
            VcTypeInfo(config_id=d.config_id, display_name=d.display_name or d.config_id)
            for d in _config.vc_definitions
        ]
        return self.helper.success(
            VcTypesResponse, VcTypesResponseBody, VcTypesResultPayload(vc_types=types)
        )

    @require_permissions({ISSUE_PERMISSION})
    async def lookup_beneficiary(
        self, request: Request, lookup_request: LookupBeneficiaryRequest
    ) -> LookupBeneficiaryResponse:
        payload = lookup_request.request_body.request_payload
        # Looking a citizen up by national id is the agent action most worth
        # being able to review later, so record the record it resolved to. The
        # national id itself is deliberately NOT stored: the audit trail should
        # let someone retrace what was done without becoming a second copy of
        # the registry's identifiers.
        set_audit(request, action="lookup_beneficiary", resource_type="registry_record")
        # The CHOSEN type, not the first one. The definition supplies the view and
        # record-id column this lookup runs against, so defaulting here would query
        # the wrong view whenever a deployment configures types with different
        # views -- and would do it silently, resolving either nothing or the wrong
        # record.
        vc = _config.get_vc_definition(payload.vc_type)
        if vc is None:
            return self.helper.error(
                LookupBeneficiaryResponse, LookupBeneficiaryResponseBody,
                "G2P-VC-501",
                f"Unknown credential type {payload.vc_type!r}."
                if payload.vc_type
                else "No credential definitions are configured.",
                lookup_request,
            )
        try:
            row, reason = await self.registry_lookup_service.resolve_by_national_id(
                payload.national_id, vc
            )
        except RegistryLookupError as error:
            return self.helper.error(
                LookupBeneficiaryResponse, LookupBeneficiaryResponseBody,
                error.code, error.message, lookup_request,
            )
        set_audit(
            request,
            resource_id=str(row[vc.record_id_column]),
            detail={"eligible": reason is None, "reason": reason,
                    "vc_type": vc.config_id},
        )
        result = LookupBeneficiaryResultPayload(
            internal_record_id=str(row[vc.record_id_column]),
            register_id=self._register_id(payload.register_id, row),
            record_name=row.get(RECORD_NAME_COLUMN),
            eligible=reason is None,
            reason=reason,
        )
        return self.helper.success(
            LookupBeneficiaryResponse, LookupBeneficiaryResponseBody, result, lookup_request
        )

    @require_permissions({ISSUE_PERMISSION})
    async def start_authentication(
        self, request: Request, auth_request: StartAuthenticationRequest
    ) -> StartAuthenticationResponse:
        payload = auth_request.request_body.request_payload
        # The beneficiary's consent step. Worth its own event: it names the
        # record whose authentication was demanded, and by whom.
        set_audit(
            request,
            action="start_beneficiary_authentication",
            resource_type="registry_record",
            resource_id=payload.internal_record_id,
        )
        register_id = self._register_id(payload.register_id)
        if not register_id:
            return self.helper.error(
                StartAuthenticationResponse, StartAuthenticationResponseBody,
                "G2P-VC-501",
                "No register configured for VC issuance (vc_register_id).",
                auth_request,
            )
        try:
            # Read the record's foundational_id from the manifestation's VC view
            # and hand it to core. Core can also resolve it from the concrete
            # register model, but that model ships in the manifestation's own
            # package, which this service deliberately does not install -- it
            # works off the view so the Registry Platform can own it for every
            # registry. Without this the authentication completes and is then
            # rejected at the binding check as having no foundational_id.
            vc = _config.get_vc_definition(payload.vc_type)
            if vc is None:
                return self.helper.error(
                    StartAuthenticationResponse, StartAuthenticationResponseBody,
                    "G2P-VC-501",
                    f"Unknown credential type {payload.vc_type!r}."
                    if payload.vc_type
                    else "No credential definitions are configured.",
                    auth_request,
                )
            row = await self.registry_lookup_service.get_record(
                payload.internal_record_id, vc
            )
            authentication_id, url, provider_name = await self.beneficiary_auth_service.start(
                register_id=register_id,
                internal_record_id=payload.internal_record_id,
                agent_id=self._agent_id(request),
                provider_id=payload.provider_id,
                foundational_id=row.get(FOUNDATIONAL_ID_COLUMN),
            )
        except BeneficiaryAuthError as error:
            return self.helper.error(
                StartAuthenticationResponse, StartAuthenticationResponseBody,
                error.code, error.message, auth_request,
            )
        except Exception as error:  # noqa: BLE001 - surfaced to the agent verbatim
            _logger.exception("Could not start beneficiary authentication")
            return self.helper.error(
                StartAuthenticationResponse, StartAuthenticationResponseBody,
                "G2P-VC-500", str(error), auth_request,
            )
        return self.helper.success(
            StartAuthenticationResponse, StartAuthenticationResponseBody,
            StartAuthenticationResultPayload(
                authentication_id=authentication_id,
                authorization_url=url,
                provider_name=provider_name,
            ),
            auth_request,
        )

    @require_permissions({ISSUE_PERMISSION})
    async def authentication_status(
        self, request: Request, status_request: AuthenticationStatusRequest
    ) -> AuthenticationStatusResponse:
        payload = status_request.request_body.request_payload
        # Polled every couple of seconds while the agent waits, so it is the
        # noisiest event in the store. Kept because the moment a beneficiary
        # authorises is exactly what an issuance is later justified by.
        set_audit(
            request,
            action="check_beneficiary_authentication",
            resource_type="registry_record",
            resource_id=payload.internal_record_id,
        )
        auth, authorised, reason, remaining = await self.beneficiary_auth_service.authorisation(
            internal_record_id=payload.internal_record_id,
            authentication_id=payload.authentication_id,
        )
        set_audit(request, detail={"authorised": authorised,
                                  "status": auth.status if auth else "NONE"})
        result = AuthenticationStatusResultPayload(
            authentication_id=auth.authentication_id if auth else None,
            status=auth.status if auth else "NONE",
            authorised=authorised,
            expires_in_seconds=remaining,
            reason=reason,
        )
        return self.helper.success(
            AuthenticationStatusResponse, AuthenticationStatusResponseBody,
            result, status_request,
        )

    @require_permissions({ISSUE_PERMISSION})
    async def issue(self, request: Request, issue_request: IssueVcRequest):
        """Issue and return the printable credential.

        On success the PDF itself is the response body — the agent downloads it
        straight to the machine attached to their printer. Nothing is written to
        the pod, so any replica can serve any request. The issuance identifiers
        travel in headers so the client can show or log them alongside the file.
        """
        payload = issue_request.request_body.request_payload
        agent_id = self._agent_id(request)

        # `g2p_vc_issuances` already records the successful issuances. The audit
        # event is the other half: it survives independently of the registry
        # database and covers the attempts that never became a row.
        set_audit(
            request,
            action="issue_credential",
            resource_type="verifiable_credential",
            resource_id=payload.internal_record_id,
            detail={"vc_type": payload.vc_type,
                    "reprint_of": payload.reprint_of},
        )

        def fail(code: str, message: str, status_code: int = 400):
            # Every exit through here is a credential NOT issued, each for a
            # different reason -- unknown type, beneficiary not authenticated,
            # Certify refused, PDF failed. The reason is the whole value of the
            # record, so carry it rather than just the status.
            set_audit(request, outcome="failure",
                      detail={"error_code": code, "reason": message})
            return Response(
                content=self.helper.error(
                    IssueVcResponse, IssueVcResponseBody, code, message, issue_request
                ).model_dump_json(),
                media_type="application/json",
                status_code=status_code,
            )

        vc = _config.get_vc_definition(payload.vc_type)
        if vc is None:
            return fail("G2P-VC-501", f"Unknown credential type {payload.vc_type!r}.")

        # The beneficiary's authentication is the gate. Checked here, at the point
        # of issue, rather than trusting a check the client made earlier — the
        # window may well have elapsed while the agent was reading the screen.
        auth, authorised, reason, _ = await self.beneficiary_auth_service.authorisation(
            internal_record_id=payload.internal_record_id,
            authentication_id=payload.authentication_id,
        )
        if not authorised:
            return fail("G2P-VC-401", reason or "The beneficiary is not authenticated.")

        register_id = ""
        try:
            row = await self.registry_lookup_service.get_record(payload.internal_record_id, vc)
            register_id = self._register_id(None, row)
            claims = self.registry_lookup_service.claims_from_row(row, vc)
        except RegistryLookupError as error:
            return fail(error.code, error.message)

        try:
            credential = await self.certify_issuance_service.issue(
                claims, vc.config_id, vc.credential_types
            )
        except CertifyIssuanceError as error:
            # Record the failure: an issuance that authenticated a beneficiary and
            # then failed is precisely what someone will need explained later.
            await self.issuance_log_service.record(
                register_id=register_id,
                internal_record_id=payload.internal_record_id,
                vc_type=vc.config_id,
                issued_by=agent_id,
                authentication_id=auth.authentication_id if auth else None,
                status=VcIssuanceStatusEnum.failed.value,
                failure_reason=error.message,
                reprint_of=payload.reprint_of,
            )
            return fail(error.code, error.message, status_code=502)

        try:
            pdf_bytes = self.pdf_render_service.render(claims, credential, vc)
        except Exception as error:  # noqa: BLE001
            _logger.exception("Credential was issued but the PDF could not be rendered")
            await self.issuance_log_service.record(
                register_id=register_id,
                internal_record_id=payload.internal_record_id,
                vc_type=vc.config_id,
                issued_by=agent_id,
                credential_id=self.issuance_log_service.credential_id_of(credential),
                authentication_id=auth.authentication_id if auth else None,
                status=VcIssuanceStatusEnum.failed.value,
                failure_reason=f"PDF rendering failed: {error}",
                reprint_of=payload.reprint_of,
            )
            return fail("G2P-VC-500", f"PDF rendering failed: {error}", status_code=500)

        entry = await self.issuance_log_service.record(
            register_id=register_id,
            internal_record_id=payload.internal_record_id,
            vc_type=vc.config_id,
            issued_by=agent_id,
            credential_id=self.issuance_log_service.credential_id_of(credential),
            authentication_id=auth.authentication_id if auth else None,
            reprint_of=payload.reprint_of,
        )

        set_audit(
            request,
            outcome="success",
            subject=register_id or None,
            detail={
                "issuance_id": entry.issuance_id,
                "credential_id": entry.credential_id,
                "vc_type": vc.config_id,
                "authentication_id": auth.authentication_id if auth else None,
            },
        )

        filename = f"{vc.config_id}-{entry.issuance_id}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Issuance-Id": entry.issuance_id,
                "X-Credential-Id": entry.credential_id or "",
                "X-Vc-Type": vc.config_id,
            },
        )
