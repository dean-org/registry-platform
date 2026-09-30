import logging
import re
from typing import Any, Dict, Optional, Tuple

from openg2p_fastapi_common.context import dbengine
from openg2p_fastapi_common.service import BaseService
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker

from ..config import CROP_LINK_COLUMN, Settings, VcDefinition

_config = Settings.get_config()
_logger = logging.getLogger(_config.logging_default_logger_name)

# View and column names come from operator configuration, never from a request.
# They are still validated before being interpolated, so a misconfiguration
# fails loudly here instead of becoming a malformed (or dangerous) statement.
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Columns the contract reserves. Everything else in the view becomes a claim.
RECORD_ID_COLUMN = "internal_record_id"
FOUNDATIONAL_ID_COLUMN = "foundational_id"
RECORD_STATUS_COLUMN = "record_status"
RECORD_NAME_COLUMN = "record_name"
REGISTER_ID_COLUMN = "register_id"
_RESERVED = {
    RECORD_ID_COLUMN,
    FOUNDATIONAL_ID_COLUMN,
    RECORD_STATUS_COLUMN,
    RECORD_NAME_COLUMN,
    REGISTER_ID_COLUMN,
}

ACTIVE_STATUS = "ACTIVE"


class RegistryLookupError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


class RegistryLookupService(BaseService):
    """Reads the manifestation's VC view.

    The Registry Platform owns the *contract*; each manifestation supplies the
    view, because the claim fields differ per registry. The view must expose
    `internal_record_id` and `foundational_id`, should expose `record_status`,
    and may expose `record_name` / `register_id`. Every other column is treated
    as a credential claim.

    Concrete register tables are declared by the extension, not by core
    (`G2PRegister` is abstract), so going through the view is also what keeps
    this service independent of any one registry's schema.
    """

    @staticmethod
    def _validate(name: str, what: str) -> str:
        if not name or not _IDENTIFIER.match(name):
            raise RegistryLookupError(
                "G2P-VC-500", f"Invalid {what} in configuration: {name!r}"
            )
        return name

    def _session_maker(self):
        return async_sessionmaker(dbengine.get(), expire_on_commit=False)

    async def _fetch_one(self, vc: VcDefinition, where_column: str, value: str):
        view = self._validate(vc.view, "VC view name")
        column = self._validate(where_column, "lookup column")
        query = f'SELECT * FROM {view} WHERE "{column}" = :value'  # noqa: S608
        async with self._session_maker()() as session:
            result = await session.execute(text(query), {"value": value})
            rows = result.mappings().all()
        if not rows:
            return None
        if len(rows) > 1:
            # The view is expected to be one row per record. More than one means
            # the manifestation's view is wrong; issuing from an arbitrary row
            # would silently credential the wrong data.
            raise RegistryLookupError(
                "G2P-VC-409",
                f"{len(rows)} rows in {view} for {column}={value!r}; the VC view must "
                "return exactly one row per record",
            )
        return dict(rows[0])

    async def resolve_by_national_id(
        self, national_id: str, vc: VcDefinition
    ) -> Tuple[Dict[str, Any], Optional[str]]:
        """Locate a record by its national (foundational) ID.

        Returns (row, ineligibility_reason). A reason means the record exists but
        must not be issued to — the caller reports that rather than a bare
        "not found", which an agent cannot act on.
        """
        row = await self._fetch_one(vc, FOUNDATIONAL_ID_COLUMN, national_id)
        if row is None:
            raise RegistryLookupError(
                "G2P-VC-404",
                "No registry record found for that ID. A credential can only be "
                "issued to someone already registered.",
            )
        if not row.get(RECORD_ID_COLUMN):
            raise RegistryLookupError(
                "G2P-VC-500",
                f"The VC view {vc.view} does not expose {RECORD_ID_COLUMN}",
            )

        reason = None
        status = row.get(RECORD_STATUS_COLUMN)
        # The view is expected to be active-only; when it also exposes the status
        # we can tell the agent *why* rather than just failing to find anything.
        if status is not None and str(status).upper() != ACTIVE_STATUS:
            reason = f"Record status is {status}; only {ACTIVE_STATUS} records can be issued a credential."
        return row, reason

    async def get_crop_record(
        self, foundational_id: str, vc: VcDefinition
    ) -> Dict[str, Any]:
        """Latest crop register row for a farmer, found by link_foundational_id.

        A farmer may have several crop rows (seasons, parcels). The credential
        carries one crop, so the most recently created row is used rather than
        failing — this is a deliberate difference from `_fetch_one`.
        """
        table = vc.view
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$", table or ""):
            raise RegistryLookupError(
                "G2P-VC-500", f"Invalid crop table in configuration: {table!r}"
            )
        link_column = self._validate(CROP_LINK_COLUMN, "lookup column")
        query = (
            f'SELECT * FROM {table} WHERE "{link_column}" = :value '  # noqa: S608
            "ORDER BY created_at DESC NULLS LAST LIMIT 1"
        )
        async with self._session_maker()() as session:
            result = await session.execute(text(query), {"value": foundational_id})
            row = result.mappings().first()
        if row is None:
            raise RegistryLookupError(
                "G2P-VC-404",
                "No crop record is registered for this farmer.",
            )
        return dict(row)

    async def get_record(self, internal_record_id: str, vc: VcDefinition) -> Dict[str, Any]:
        row = await self._fetch_one(vc, vc.record_id_column, internal_record_id)
        if row is None:
            raise RegistryLookupError(
                "G2P-VC-404", f"No record {internal_record_id} in {vc.view}"
            )
        return row

    @staticmethod
    def claims_from_row(row: Dict[str, Any], vc: VcDefinition) -> Dict[str, Any]:
        """Project a view row onto the credential's claims.

        Reserved contract columns never become claims — `foundational_id` in
        particular is used to bind the authentication and is deliberately not
        stamped into the credential unless the manifestation asks for it by name.
        """
        if vc.claim_columns:
            missing = [c for c in vc.claim_columns if c not in row]
            if missing:
                raise RegistryLookupError(
                    "G2P-VC-500",
                    f"VC view {vc.view} is missing configured claim columns: {missing}",
                )
            selected = vc.claim_columns
        else:
            selected = [k for k in row.keys() if k not in _RESERVED]

        claims: Dict[str, Any] = {}
        for key in selected:
            value = row.get(key)
            if value is None:
                continue
            # Certify's Velocity templates substitute strings; dates and numbers
            # would otherwise render with Python's repr.
            claims[key] = value if isinstance(value, str) else str(value)
        return claims
