# ruff: noqa: E402
import logging

from .config import Settings

_config = Settings.get_config()

from openg2p_fastapi_common.app import Initializer as BaseInitializer
from openg2p_registry_core.app import Initializer as CoreInitializer
from openg2p_registry_extensions.app import Initializer as ExtensionsInitializer

from .controllers import VcIssuanceController, VcVerificationController
from .helpers import RequestResponseHelper
from .services import (
    CredentialVerificationService,
    BeneficiaryAuthService,
    CertifyIssuanceService,
    CredIssuerService,
    IssuanceLogService,
    PdfRenderService,
    RegistryLookupService,
)
from .services.land_record_credissuer_service import (
    LandRecordCredIssuerService,
)
_logger = logging.getLogger(_config.logging_default_logger_name)


class Initializer(BaseInitializer):
    def initialize(self, **kwargs):
        RequestResponseHelper()
        RegistryLookupService()
        BeneficiaryAuthService()
        CertifyIssuanceService()
        CredIssuerService()
        LandRecordCredIssuerService()
        CredentialVerificationService()
        PdfRenderService()
        IssuanceLogService()

        # The feature switch inside the service. When off, the issuance routes
        # are never mounted — they are absent from the app and from the OpenAPI
        # document, rather than present and returning an error. That way a
        # deployment that has not opted in exposes no issuance surface at all.
        if _config.vc_issuance_enabled:
            VcIssuanceController().post_init()
            _logger.info("VC issuance is ENABLED; agent portal issuance routes mounted.")
        else:
            _logger.info(
                "VC issuance is DISABLED (registry_agent_portal_api_vc_issuance_enabled). "
                "No issuance routes are mounted."
            )

        # Verification is switched independently of issuance: checking a card
        # someone presents is a different act from creating one, and a
        # deployment may reasonably want only the first.
        if _config.vc_verification_enabled:
            VcVerificationController().post_init()
            _logger.info(
                "VC verification is ENABLED; agent portal verification routes mounted."
            )
        else:
            _logger.info(
                "VC verification is DISABLED "
                "(registry_agent_portal_api_vc_verification_enabled). "
                "No verification routes are mounted."
            )

    def migrate_database(self, args):
        _logger.info("Starting database migration")

        CoreInitializer().get_component().migrate_database(args)
        ExtensionsInitializer().get_component().migrate_database(args)

        _logger.info("Database migration completed")
