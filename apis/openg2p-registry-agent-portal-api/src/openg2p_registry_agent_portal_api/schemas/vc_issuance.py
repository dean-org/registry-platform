from typing import Any, Dict, List, Optional

from openg2p_fastapi_common.schemas import (
    G2PRequest,
    G2PRequestBody,
    G2PResponse,
    G2PResponseBody,
)
from pydantic import BaseModel


# ── 1. Resolve the beneficiary ────────────────────────────────────────────────
class LookupBeneficiaryPayload(BaseModel):
    """The agent enters or scans the beneficiary's national ID.

    This only *locates* the record. Everything downstream is keyed on the
    resolved internal_record_id, never on this value.
    """

    national_id: str
    register_id: Optional[str] = None
    # Which credential definition this call is for. Lookup and authentication
    # resolve the record through the definition's VIEW, so a deployment whose
    # types read different views needs this -- without it both steps silently
    # use the first definition while the agent believes they used the one they
    # chose. Optional: unset means the only (or first) definition, which is
    # correct whenever all types share a view.
    vc_type: Optional[str] = None


class LookupBeneficiaryRequestBody(G2PRequestBody):
    request_payload: LookupBeneficiaryPayload


class LookupBeneficiaryRequest(G2PRequest):
    request_body: LookupBeneficiaryRequestBody


class LookupBeneficiaryResultPayload(BaseModel):
    internal_record_id: str
    register_id: str
    record_name: Optional[str] = None
    # False when the record exists but must not be issued to (e.g. not ACTIVE).
    eligible: bool = True
    reason: Optional[str] = None


class LookupBeneficiaryResponseBody(G2PResponseBody):
    response_payload: Optional[LookupBeneficiaryResultPayload] = None


class LookupBeneficiaryResponse(G2PResponse):
    response_body: LookupBeneficiaryResponseBody


# ── 2. Start the beneficiary's eSignet authentication ─────────────────────────
class StartAuthenticationPayload(BaseModel):
    internal_record_id: str
    register_id: Optional[str] = None
    # Which credential definition this call is for. Lookup and authentication
    # resolve the record through the definition's VIEW, so a deployment whose
    # types read different views needs this -- without it both steps silently
    # use the first definition while the agent believes they used the one they
    # chose. Optional: unset means the only (or first) definition, which is
    # correct whenever all types share a view.
    vc_type: Optional[str] = None
    provider_id: Optional[str] = None


class StartAuthenticationRequestBody(G2PRequestBody):
    request_payload: StartAuthenticationPayload


class StartAuthenticationRequest(G2PRequest):
    request_body: StartAuthenticationRequestBody


class StartAuthenticationResultPayload(BaseModel):
    authentication_id: str
    # The agent's client opens this so the beneficiary can authenticate.
    authorization_url: str
    provider_name: Optional[str] = None


class StartAuthenticationResponseBody(G2PResponseBody):
    response_payload: Optional[StartAuthenticationResultPayload] = None


class StartAuthenticationResponse(G2PResponse):
    response_body: StartAuthenticationResponseBody


# ── 3. Poll the authentication ────────────────────────────────────────────────
class AuthenticationStatusPayload(BaseModel):
    internal_record_id: str
    authentication_id: Optional[str] = None


class AuthenticationStatusRequestBody(G2PRequestBody):
    request_payload: AuthenticationStatusPayload


class AuthenticationStatusRequest(G2PRequest):
    request_body: AuthenticationStatusRequestBody


class AuthenticationStatusResultPayload(BaseModel):
    authentication_id: Optional[str] = None
    status: str
    # True only while the authentication both succeeded and is still inside the
    # VC window — i.e. the client may proceed to issue.
    authorised: bool = False
    expires_in_seconds: Optional[int] = None
    reason: Optional[str] = None


class AuthenticationStatusResponseBody(G2PResponseBody):
    response_payload: Optional[AuthenticationStatusResultPayload] = None


class AuthenticationStatusResponse(G2PResponse):
    response_body: AuthenticationStatusResponseBody


# ── 4. Issue ──────────────────────────────────────────────────────────────────
class IssueVcPayload(BaseModel):
    internal_record_id: str
    authentication_id: Optional[str] = None
    # Which credential definition to issue. Defaults to the only one configured.
    vc_type: Optional[str] = None
    # Set when replacing a lost or damaged paper credential.
    reprint_of: Optional[str] = None
    credential_template: Optional[str] = None


class IssueVcRequestBody(G2PRequestBody):
    request_payload: IssueVcPayload


class IssueVcRequest(G2PRequest):
    request_body: IssueVcRequestBody


class IssueVcResultPayload(BaseModel):
    issuance_id: str
    credential_id: Optional[str] = None
    vc_type: str
    claims: Dict[str, Any] = {}


class IssueVcResponseBody(G2PResponseBody):
    response_payload: Optional[IssueVcResultPayload] = None


class IssueVcResponse(G2PResponse):
    response_body: IssueVcResponseBody


# ── Listing what this deployment can issue ────────────────────────────────────
class VcTypeInfo(BaseModel):
    config_id: str
    display_name: Optional[str] = None


class VcTypesResultPayload(BaseModel):
    vc_types: List[VcTypeInfo] = []


class VcTypesResponseBody(G2PResponseBody):
    response_payload: Optional[VcTypesResultPayload] = None


class VcTypesResponse(G2PResponse):
    response_body: VcTypesResponseBody
