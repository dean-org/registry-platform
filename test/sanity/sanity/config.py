import os
from dataclasses import dataclass, field
from typing import List, Optional

from .testkey import DEFAULT_KID, DEFAULT_PARTNER_ID, TEST_PRIVATE_KEY_PEM


def _bool(value, default=False):
    if value is None:
        return default
    return str(value).lower() in ("1", "true", "yes", "on")


def _list(value, default):
    if not value:
        return list(default)
    return [s.strip() for s in value.split(",") if s.strip()]


# The consent scopes the DCI e2e requests.
#
# These MUST be top-level keys of the register's outgoing DCI template
# (openg2p_farmer_to_dci.json.j2) — clamping is a strict allow-list over the
# rendered record's top-level keys, so a scope naming anything else silently
# clamps the record to {}. The farmer template emits exactly six:
#   farmer_personal_details, family_details, farm_details,
#   machineries_details, registration_date, last_updated
# Clamping has no sub-field granularity: `farmer_personal_details` is
# all-or-nothing (it carries birth_date and phone_number with it).
DEFAULT_DATA_SCOPES = ["farmer_personal_details"]

# Scopes deliberately NOT consented to — the e2e asserts these never appear.
DEFAULT_DENIED_SCOPES = ["family_details", "farm_details", "machineries_details"]

# Roles the seeded test user is granted on the registry's Keycloak client.
DEFAULT_STAFF_ROLES = ["Operations Administrator", "Technical Administrator"]


@dataclass
class Config:
    # ── Farmer Registry partner-api (the PEP under test) ────────────────────
    partner_base_url: str  # e.g. http://<release>-partner-api  (no ingress path prefix)
    verify_tls: bool
    run_e2e: bool
    readiness_timeout: int

    # ── Shared sanity partner identity (same partner as CM) ─────────────────
    pm_partner_id: str       # PM reference, e.g. PARTNER_CM_SANITY
    pm_kid: str              # kid registered in PM
    pm_private_key_pem: str  # PEM private key the e2e signs both JWSs with

    # ── DCI request shaping ─────────────────────────────────────────────────
    dci_sender_id: str       # envelope sender; PARTNER_<upper> must equal pm_partner_id
    dci_receiver_id: str     # envelope receiver (the registry)
    reg_type: str            # register mnemonic, e.g. Farmer
    reg_record_type: str     # DCI record type for the payload shape
    search_text: str         # value to search for; matched as ILIKE '%text%'

    # ── Consent Manager binding + consent object ────────────────────────────
    cm_staff_url: str        # CM staff-portal-api base (to seed the binding + policy)
    cm_audience: str         # the consent object's `aud` == the CM binding audience
    controller_id: str       # data_controller (must match the binding's controller)
    data_scopes: List[str] = field(default_factory=lambda: list(DEFAULT_DATA_SCOPES))
    denied_scopes: List[str] = field(default_factory=lambda: list(DEFAULT_DENIED_SCOPES))

    # ── Partner Management seeding (key) ────────────────────────────────────
    pm_partner_api_url: str = ""   # PM key-fetch base (servability check)
    pm_admin_url: str = ""         # PM staff-portal-api base (to onboard/approve)
    pm_admin_token_url: str = ""
    pm_admin_client_id: str = "partner-management"
    pm_admin_client_secret: str = ""

    # ── Consent Manager admin auth (to create the binding via staff API) ────
    cm_auth_enabled: bool = True
    cm_token_url: str = ""
    cm_client_id: str = "consent-manager"
    cm_client_secret: str = ""

    # ── Registry staff-portal-api (change-request e2e) ───────────────────────
    #
    # Authenticated as the suite's OWN seeded user via the password grant. The
    # registry's Keycloak client is a browser OIDC client with no service
    # account, and keycloak-init's demo users get a TEMPORARY password (so
    # Keycloak forces UPDATE_PASSWORD and their password grant fails). See
    # sanity/keycloak_seed.py and sanity/staff.py.
    staff_base_url: str = ""
    staff_token_url: str = ""
    staff_client_id: str = ""
    staff_client_secret: str = ""
    # The suite's own seeded identity — raises the CR and clears every stage.
    staff_username: str = "sanity-e2e"
    staff_password: str = ""
    staff_roles: List[str] = field(default_factory=lambda: list(DEFAULT_STAFF_ROLES))

    # ── Keycloak admin (to provision the test user) ───────────────────────────
    keycloak_base_url: str = ""
    keycloak_realm: str = "staff"
    keycloak_admin_user: str = "admin"
    keycloak_admin_password: str = ""
    # AWE admin role, granted to the sanity user so it can approve EVERY task on
    # the change request — not just its own. The shipped policy stages use
    # mode='all' and name demo approvers (alex.carter / nina.patel) whose
    # temporary passwords the suite can't log in with; AWE lets a caller holding
    # this role decide any task regardless of assignee, so one identity clears
    # the whole workflow. It is a CLIENT role on the awe-admin-portal client.
    awe_admin_client_id: str = "awe-admin-portal"
    awe_admin_role: str = "AWE_ADMIN"
    # Register the CR is raised against (Farmer), and the UI coordinates the
    # change-request payload requires.
    farmer_register_id: str = "a1a4d25a-1cd4-4356-abac-985a0b3c6bcd"
    cr_tab_id: str = "farmer_farmer_tab"
    cr_section_id: str = "farmer_farmer_personal_identification_section_01"
    # How long to wait for AWE's decision webhook to be applied by the registry.
    awe_settle_timeout: int = 90
    # Safety bound on the stage-walk loop (a policy has far fewer stages).
    max_approval_rounds: int = 5
    # How long to keep retrying the first permission-gated call (create change
    # request) while the registry's permission path warms up after install.
    auth_ready_timeout: int = 120

    # ── Agent Portal API (VC issuance) ───────────────────────────────────────
    # Agents are their OWN Keycloak realm, so none of the staff_* settings above
    # apply here. Everything is optional: when unset, the VC tests skip rather
    # than fail, so this suite still runs green on an install that has not
    # enabled the capability.
    agent_base_url: str = ""
    agent_token_url: str = ""
    agent_client_id: str = "registry-agent-portal"
    agent_client_secret: str = ""
    agent_username: str = "sanity-agent"
    agent_password: str = ""
    agent_realm: str = "agent"
    # The national (foundational) ID the VC e2e issues against. Seeded by the
    # suite so the test does not depend on demo data being loaded.
    vc_national_id: str = "TEST_SANITY_VC_0001"
    vc_type: str = ""

    # ── Databases (see sanity/db.py for why each is needed) ──────────────────
    registry_dsn: Optional[dict] = None
    awe_dsn: Optional[dict] = None
    audit_dsn: Optional[dict] = None
    audit_timeout: int = 60

    @classmethod
    def from_env(cls) -> "Config":
        from .db import _dsn

        staff_client_id = os.environ.get("SANITY_STAFF_CLIENT_ID", "")
        return cls(
            partner_base_url=(os.environ.get("SANITY_PARTNER_BASE_URL") or "http://localhost:8000").rstrip("/"),
            verify_tls=_bool(os.environ.get("SANITY_VERIFY_TLS"), True),
            run_e2e=_bool(os.environ.get("SANITY_RUN_E2E"), False),
            readiness_timeout=int(os.environ.get("SANITY_READINESS_TIMEOUT", "180")),
            pm_partner_id=os.environ.get("SANITY_PM_PARTNER_ID") or DEFAULT_PARTNER_ID,
            pm_kid=os.environ.get("SANITY_PM_KID") or DEFAULT_KID,
            pm_private_key_pem=os.environ.get("SANITY_PM_PRIVATE_KEY_PEM") or TEST_PRIVATE_KEY_PEM,
            dci_sender_id=os.environ.get("SANITY_DCI_SENDER_ID") or "cm_sanity",
            dci_receiver_id=os.environ.get("SANITY_DCI_RECEIVER_ID") or "farmer-registry",
            reg_type=os.environ.get("SANITY_DCI_REG_TYPE") or "Farmer",
            reg_record_type=os.environ.get("SANITY_DCI_REG_RECORD_TYPE") or "spdci-extensions-dci:Farmer",
            search_text=os.environ.get("SANITY_DCI_SEARCH_TEXT") or "SANITY-FARMER-0001",
            cm_staff_url=(os.environ.get("SANITY_CM_STAFF_URL") or "").rstrip("/"),
            cm_audience=os.environ.get("SANITY_CM_AUDIENCE") or "FR_SANITY_PARTNER",
            controller_id=os.environ.get("SANITY_CONTROLLER_ID") or "fr-sanity-controller",
            data_scopes=_list(os.environ.get("SANITY_DATA_SCOPES"), DEFAULT_DATA_SCOPES),
            denied_scopes=_list(os.environ.get("SANITY_DENIED_SCOPES"), DEFAULT_DENIED_SCOPES),
            pm_partner_api_url=(os.environ.get("SANITY_PM_PARTNER_API_URL") or "").rstrip("/"),
            pm_admin_url=(os.environ.get("SANITY_PM_ADMIN_URL") or "").rstrip("/"),
            pm_admin_token_url=os.environ.get("SANITY_PM_ADMIN_TOKEN_URL", ""),
            pm_admin_client_id=os.environ.get("SANITY_PM_ADMIN_CLIENT_ID", "partner-management"),
            pm_admin_client_secret=os.environ.get("SANITY_PM_ADMIN_CLIENT_SECRET", ""),
            cm_auth_enabled=_bool(os.environ.get("SANITY_CM_AUTH_ENABLED"), True),
            cm_token_url=os.environ.get("SANITY_CM_TOKEN_URL", ""),
            cm_client_id=os.environ.get("SANITY_CM_CLIENT_ID", "consent-manager"),
            cm_client_secret=os.environ.get("SANITY_CM_CLIENT_SECRET", ""),
            staff_base_url=(os.environ.get("SANITY_STAFF_BASE_URL") or "").rstrip("/"),
            staff_token_url=os.environ.get("SANITY_STAFF_TOKEN_URL", ""),
            staff_client_id=staff_client_id,
            staff_client_secret=os.environ.get("SANITY_STAFF_CLIENT_SECRET", ""),
            staff_username=os.environ.get("SANITY_STAFF_USERNAME") or "sanity-e2e",
            staff_password=os.environ.get("SANITY_STAFF_PASSWORD", ""),
            staff_roles=_list(os.environ.get("SANITY_STAFF_ROLES"), DEFAULT_STAFF_ROLES),
            keycloak_base_url=(os.environ.get("SANITY_KEYCLOAK_BASE_URL") or "").rstrip("/"),
            keycloak_realm=os.environ.get("SANITY_KEYCLOAK_REALM") or "staff",
            keycloak_admin_user=os.environ.get("SANITY_KEYCLOAK_ADMIN_USER") or "admin",
            keycloak_admin_password=os.environ.get("SANITY_KEYCLOAK_ADMIN_PASSWORD", ""),
            awe_admin_client_id=os.environ.get("SANITY_AWE_ADMIN_CLIENT_ID") or "awe-admin-portal",
            awe_admin_role=os.environ.get("SANITY_AWE_ADMIN_ROLE") or "AWE_ADMIN",
            farmer_register_id=(
                os.environ.get("SANITY_FARMER_REGISTER_ID")
                or "a1a4d25a-1cd4-4356-abac-985a0b3c6bcd"
            ),
            cr_tab_id=os.environ.get("SANITY_CR_TAB_ID") or "farmer_farmer_tab",
            cr_section_id=os.environ.get("SANITY_CR_SECTION_ID") or "farmer_farmer_personal_identification_section_01",
            awe_settle_timeout=int(os.environ.get("SANITY_AWE_SETTLE_TIMEOUT", "90")),
            max_approval_rounds=int(os.environ.get("SANITY_MAX_APPROVAL_ROUNDS", "5")),
            auth_ready_timeout=int(os.environ.get("SANITY_AUTH_READY_TIMEOUT", "120")),
            agent_base_url=(os.environ.get("SANITY_AGENT_BASE_URL") or "").rstrip("/"),
            agent_token_url=os.environ.get("SANITY_AGENT_TOKEN_URL", ""),
            agent_client_id=os.environ.get("SANITY_AGENT_CLIENT_ID") or "registry-agent-portal",
            agent_client_secret=os.environ.get("SANITY_AGENT_CLIENT_SECRET", ""),
            agent_username=os.environ.get("SANITY_AGENT_USERNAME") or "sanity-agent",
            agent_password=os.environ.get("SANITY_AGENT_PASSWORD", ""),
            agent_realm=os.environ.get("SANITY_AGENT_REALM") or "agent",
            vc_national_id=os.environ.get("SANITY_VC_NATIONAL_ID") or "TEST_SANITY_VC_0001",
            vc_type=os.environ.get("SANITY_VC_TYPE", ""),
            registry_dsn=_dsn(
                os.environ.get("SANITY_REGISTRY_PGHOST"), os.environ.get("SANITY_REGISTRY_PGPORT"),
                os.environ.get("SANITY_REGISTRY_PGDATABASE"), os.environ.get("SANITY_REGISTRY_PGUSER"),
                os.environ.get("SANITY_REGISTRY_PGPASSWORD"),
            ),
            awe_dsn=_dsn(
                os.environ.get("SANITY_AWE_PGHOST"), os.environ.get("SANITY_AWE_PGPORT"),
                os.environ.get("SANITY_AWE_PGDATABASE"), os.environ.get("SANITY_AWE_PGUSER"),
                os.environ.get("SANITY_AWE_PGPASSWORD"),
            ),
            audit_dsn=_dsn(
                os.environ.get("SANITY_AUDIT_PGHOST"), os.environ.get("SANITY_AUDIT_PGPORT"),
                os.environ.get("SANITY_AUDIT_PGDATABASE"), os.environ.get("SANITY_AUDIT_PGUSER"),
                os.environ.get("SANITY_AUDIT_PGPASSWORD"),
            ),
            audit_timeout=int(os.environ.get("SANITY_AUDIT_TIMEOUT", "60")),
        )

    # Aliases so the reused CM pm_seed module (which reads cfg.token_url /
    # cfg.client_* as a fallback) works unchanged against this config.
    @property
    def token_url(self) -> str:
        return self.cm_token_url

    @property
    def client_id(self) -> str:
        return self.cm_client_id

    @property
    def client_secret(self) -> str:
        return self.cm_client_secret

    @property
    def can_reach_pm(self) -> bool:
        return bool(self.pm_partner_api_url)

    @property
    def can_reach_cm(self) -> bool:
        return bool(self.cm_staff_url)

    @property
    def can_reach_agent(self) -> bool:
        """Smoke-testable: the Agent Portal API is deployed and addressable."""
        return bool(self.agent_base_url)

    @property
    def can_login_agent(self) -> bool:
        """e2e-testable: we can obtain an agent token as well."""
        return bool(self.agent_base_url and self.agent_token_url and self.agent_password)

    @property
    def can_reach_staff(self) -> bool:
        return bool(
            self.staff_base_url
            and self.staff_token_url
            and self.staff_client_id
            and self.staff_password
        )

credential_api_base_url = "https://api.credissuer.com/api"
credential_api_token = "Bearer 8e13c6a971d24854de223a4f7a4d080795f6b210"
credential_api_template_id = "82D94F756B7A"
credential_api_org_code = "FARME-0E7VU"
credential_api_issuer_email = "nudili@denipl.net"
credential_api_http_timeout = 60